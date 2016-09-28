// Package youtube provides access to the YouTube Data API.
//
// See https://developers.google.com/youtube/v3
//
// Usage example:
//
//   import "google.golang.org/api/youtube/v3"
//   ...
//   youtubeService, err := youtube.New(oauthHttpClient)
package youtube // import "google.golang.org/api/youtube/v3"

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

const apiId = "youtube:v3"
const apiName = "youtube"
const apiVersion = "v3"
const basePath = "https://www.googleapis.com/youtube/v3/"

// OAuth2 scopes used by this API.
const (
	// Manage your YouTube account
	YoutubeScope = "https://www.googleapis.com/auth/youtube"

	// Manage your YouTube account
	YoutubeForceSslScope = "https://www.googleapis.com/auth/youtube.force-ssl"

	// View your YouTube account
	YoutubeReadonlyScope = "https://www.googleapis.com/auth/youtube.readonly"

	// Manage your YouTube videos
	YoutubeUploadScope = "https://www.googleapis.com/auth/youtube.upload"

	// View and manage your assets and associated content on YouTube
	YoutubepartnerScope = "https://www.googleapis.com/auth/youtubepartner"

	// View private information of your YouTube channel relevant during the
	// audit process with a YouTube partner
	YoutubepartnerChannelAuditScope = "https://www.googleapis.com/auth/youtubepartner-channel-audit"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Activities = NewActivitiesService(s)
	s.Captions = NewCaptionsService(s)
	s.ChannelBanners = NewChannelBannersService(s)
	s.ChannelSections = NewChannelSectionsService(s)
	s.Channels = NewChannelsService(s)
	s.CommentThreads = NewCommentThreadsService(s)
	s.Comments = NewCommentsService(s)
	s.GuideCategories = NewGuideCategoriesService(s)
	s.I18nLanguages = NewI18nLanguagesService(s)
	s.I18nRegions = NewI18nRegionsService(s)
	s.LiveBroadcasts = NewLiveBroadcastsService(s)
	s.LiveStreams = NewLiveStreamsService(s)
	s.PlaylistItems = NewPlaylistItemsService(s)
	s.Playlists = NewPlaylistsService(s)
	s.Search = NewSearchService(s)
	s.Subscriptions = NewSubscriptionsService(s)
	s.Thumbnails = NewThumbnailsService(s)
	s.VideoAbuseReportReasons = NewVideoAbuseReportReasonsService(s)
	s.VideoCategories = NewVideoCategoriesService(s)
	s.Videos = NewVideosService(s)
	s.Watermarks = NewWatermarksService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Activities *ActivitiesService

	Captions *CaptionsService

	ChannelBanners *ChannelBannersService

	ChannelSections *ChannelSectionsService

	Channels *ChannelsService

	CommentThreads *CommentThreadsService

	Comments *CommentsService

	GuideCategories *GuideCategoriesService

	I18nLanguages *I18nLanguagesService

	I18nRegions *I18nRegionsService

	LiveBroadcasts *LiveBroadcastsService

	LiveStreams *LiveStreamsService

	PlaylistItems *PlaylistItemsService

	Playlists *PlaylistsService

	Search *SearchService

	Subscriptions *SubscriptionsService

	Thumbnails *ThumbnailsService

	VideoAbuseReportReasons *VideoAbuseReportReasonsService

	VideoCategories *VideoCategoriesService

	Videos *VideosService

	Watermarks *WatermarksService
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

func NewCaptionsService(s *Service) *CaptionsService {
	rs := &CaptionsService{s: s}
	return rs
}

type CaptionsService struct {
	s *Service
}

func NewChannelBannersService(s *Service) *ChannelBannersService {
	rs := &ChannelBannersService{s: s}
	return rs
}

type ChannelBannersService struct {
	s *Service
}

func NewChannelSectionsService(s *Service) *ChannelSectionsService {
	rs := &ChannelSectionsService{s: s}
	return rs
}

type ChannelSectionsService struct {
	s *Service
}

func NewChannelsService(s *Service) *ChannelsService {
	rs := &ChannelsService{s: s}
	return rs
}

type ChannelsService struct {
	s *Service
}

func NewCommentThreadsService(s *Service) *CommentThreadsService {
	rs := &CommentThreadsService{s: s}
	return rs
}

type CommentThreadsService struct {
	s *Service
}

func NewCommentsService(s *Service) *CommentsService {
	rs := &CommentsService{s: s}
	return rs
}

type CommentsService struct {
	s *Service
}

func NewGuideCategoriesService(s *Service) *GuideCategoriesService {
	rs := &GuideCategoriesService{s: s}
	return rs
}

type GuideCategoriesService struct {
	s *Service
}

func NewI18nLanguagesService(s *Service) *I18nLanguagesService {
	rs := &I18nLanguagesService{s: s}
	return rs
}

type I18nLanguagesService struct {
	s *Service
}

func NewI18nRegionsService(s *Service) *I18nRegionsService {
	rs := &I18nRegionsService{s: s}
	return rs
}

type I18nRegionsService struct {
	s *Service
}

func NewLiveBroadcastsService(s *Service) *LiveBroadcastsService {
	rs := &LiveBroadcastsService{s: s}
	return rs
}

type LiveBroadcastsService struct {
	s *Service
}

func NewLiveStreamsService(s *Service) *LiveStreamsService {
	rs := &LiveStreamsService{s: s}
	return rs
}

type LiveStreamsService struct {
	s *Service
}

func NewPlaylistItemsService(s *Service) *PlaylistItemsService {
	rs := &PlaylistItemsService{s: s}
	return rs
}

type PlaylistItemsService struct {
	s *Service
}

func NewPlaylistsService(s *Service) *PlaylistsService {
	rs := &PlaylistsService{s: s}
	return rs
}

type PlaylistsService struct {
	s *Service
}

func NewSearchService(s *Service) *SearchService {
	rs := &SearchService{s: s}
	return rs
}

type SearchService struct {
	s *Service
}

func NewSubscriptionsService(s *Service) *SubscriptionsService {
	rs := &SubscriptionsService{s: s}
	return rs
}

type SubscriptionsService struct {
	s *Service
}

func NewThumbnailsService(s *Service) *ThumbnailsService {
	rs := &ThumbnailsService{s: s}
	return rs
}

type ThumbnailsService struct {
	s *Service
}

func NewVideoAbuseReportReasonsService(s *Service) *VideoAbuseReportReasonsService {
	rs := &VideoAbuseReportReasonsService{s: s}
	return rs
}

type VideoAbuseReportReasonsService struct {
	s *Service
}

func NewVideoCategoriesService(s *Service) *VideoCategoriesService {
	rs := &VideoCategoriesService{s: s}
	return rs
}

type VideoCategoriesService struct {
	s *Service
}

func NewVideosService(s *Service) *VideosService {
	rs := &VideosService{s: s}
	return rs
}

type VideosService struct {
	s *Service
}

func NewWatermarksService(s *Service) *WatermarksService {
	rs := &WatermarksService{s: s}
	return rs
}

type WatermarksService struct {
	s *Service
}

// AccessPolicy: Rights management policy for YouTube resources.
type AccessPolicy struct {
	// Allowed: The value of allowed indicates whether the access to the
	// policy is allowed or denied by default.
	Allowed bool `json:"allowed,omitempty"`

	// Exception: A list of region codes that identify countries where the
	// default policy do not apply.
	Exception []string `json:"exception,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Allowed") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccessPolicy) MarshalJSON() ([]byte, error) {
	type noMethod AccessPolicy
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Activity: An activity resource contains information about an action
// that a particular channel, or user, has taken on YouTube.The actions
// reported in activity feeds include rating a video, sharing a video,
// marking a video as a favorite, commenting on a video, uploading a
// video, and so forth. Each activity resource identifies the type of
// action, the channel associated with the action, and the resource(s)
// associated with the action, such as the video that was rated or
// uploaded.
type Activity struct {
	// ContentDetails: The contentDetails object contains information about
	// the content associated with the activity. For example, if the
	// snippet.type value is videoRated, then the contentDetails object's
	// content identifies the rated video.
	ContentDetails *ActivityContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the activity.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#activity".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the
	// activity, including the activity's type and group ID.
	Snippet *ActivitySnippet `json:"snippet,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
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

// ActivityContentDetails: Details about the content of an activity: the
// video that was shared, the channel that was subscribed to, etc.
type ActivityContentDetails struct {
	// Bulletin: The bulletin object contains details about a channel
	// bulletin post. This object is only present if the snippet.type is
	// bulletin.
	Bulletin *ActivityContentDetailsBulletin `json:"bulletin,omitempty"`

	// ChannelItem: The channelItem object contains details about a resource
	// which was added to a channel. This property is only present if the
	// snippet.type is channelItem.
	ChannelItem *ActivityContentDetailsChannelItem `json:"channelItem,omitempty"`

	// Comment: The comment object contains information about a resource
	// that received a comment. This property is only present if the
	// snippet.type is comment.
	Comment *ActivityContentDetailsComment `json:"comment,omitempty"`

	// Favorite: The favorite object contains information about a video that
	// was marked as a favorite video. This property is only present if the
	// snippet.type is favorite.
	Favorite *ActivityContentDetailsFavorite `json:"favorite,omitempty"`

	// Like: The like object contains information about a resource that
	// received a positive (like) rating. This property is only present if
	// the snippet.type is like.
	Like *ActivityContentDetailsLike `json:"like,omitempty"`

	// PlaylistItem: The playlistItem object contains information about a
	// new playlist item. This property is only present if the snippet.type
	// is playlistItem.
	PlaylistItem *ActivityContentDetailsPlaylistItem `json:"playlistItem,omitempty"`

	// PromotedItem: The promotedItem object contains details about a
	// resource which is being promoted. This property is only present if
	// the snippet.type is promotedItem.
	PromotedItem *ActivityContentDetailsPromotedItem `json:"promotedItem,omitempty"`

	// Recommendation: The recommendation object contains information about
	// a recommended resource. This property is only present if the
	// snippet.type is recommendation.
	Recommendation *ActivityContentDetailsRecommendation `json:"recommendation,omitempty"`

	// Social: The social object contains details about a social network
	// post. This property is only present if the snippet.type is social.
	Social *ActivityContentDetailsSocial `json:"social,omitempty"`

	// Subscription: The subscription object contains information about a
	// channel that a user subscribed to. This property is only present if
	// the snippet.type is subscription.
	Subscription *ActivityContentDetailsSubscription `json:"subscription,omitempty"`

	// Upload: The upload object contains information about the uploaded
	// video. This property is only present if the snippet.type is upload.
	Upload *ActivityContentDetailsUpload `json:"upload,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Bulletin") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsBulletin: Details about a channel bulletin
// post.
type ActivityContentDetailsBulletin struct {
	// ResourceId: The resourceId object contains information that
	// identifies the resource associated with a bulletin post.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsBulletin) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsBulletin
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsChannelItem: Details about a resource which was
// added to a channel.
type ActivityContentDetailsChannelItem struct {
	// ResourceId: The resourceId object contains information that
	// identifies the resource that was added to the channel.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsChannelItem) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsChannelItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsComment: Information about a resource that
// received a comment.
type ActivityContentDetailsComment struct {
	// ResourceId: The resourceId object contains information that
	// identifies the resource associated with the comment.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsComment) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsComment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsFavorite: Information about a video that was
// marked as a favorite video.
type ActivityContentDetailsFavorite struct {
	// ResourceId: The resourceId object contains information that
	// identifies the resource that was marked as a favorite.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsFavorite) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsFavorite
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsLike: Information about a resource that
// received a positive (like) rating.
type ActivityContentDetailsLike struct {
	// ResourceId: The resourceId object contains information that
	// identifies the rated resource.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsLike) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsLike
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsPlaylistItem: Information about a new playlist
// item.
type ActivityContentDetailsPlaylistItem struct {
	// PlaylistId: The value that YouTube uses to uniquely identify the
	// playlist.
	PlaylistId string `json:"playlistId,omitempty"`

	// PlaylistItemId: ID of the item within the playlist.
	PlaylistItemId string `json:"playlistItemId,omitempty"`

	// ResourceId: The resourceId object contains information about the
	// resource that was added to the playlist.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "PlaylistId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsPlaylistItem) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsPlaylistItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsPromotedItem: Details about a resource which is
// being promoted.
type ActivityContentDetailsPromotedItem struct {
	// AdTag: The URL the client should fetch to request a promoted item.
	AdTag string `json:"adTag,omitempty"`

	// ClickTrackingUrl: The URL the client should ping to indicate that the
	// user clicked through on this promoted item.
	ClickTrackingUrl string `json:"clickTrackingUrl,omitempty"`

	// CreativeViewUrl: The URL the client should ping to indicate that the
	// user was shown this promoted item.
	CreativeViewUrl string `json:"creativeViewUrl,omitempty"`

	// CtaType: The type of call-to-action, a message to the user indicating
	// action that can be taken.
	//
	// Possible values:
	//   "unspecified"
	//   "visitAdvertiserSite"
	CtaType string `json:"ctaType,omitempty"`

	// CustomCtaButtonText: The custom call-to-action button text. If
	// specified, it will override the default button text for the cta_type.
	CustomCtaButtonText string `json:"customCtaButtonText,omitempty"`

	// DescriptionText: The text description to accompany the promoted item.
	DescriptionText string `json:"descriptionText,omitempty"`

	// DestinationUrl: The URL the client should direct the user to, if the
	// user chooses to visit the advertiser's website.
	DestinationUrl string `json:"destinationUrl,omitempty"`

	// ForecastingUrl: The list of forecasting URLs. The client should ping
	// all of these URLs when a promoted item is not available, to indicate
	// that a promoted item could have been shown.
	ForecastingUrl []string `json:"forecastingUrl,omitempty"`

	// ImpressionUrl: The list of impression URLs. The client should ping
	// all of these URLs to indicate that the user was shown this promoted
	// item.
	ImpressionUrl []string `json:"impressionUrl,omitempty"`

	// VideoId: The ID that YouTube uses to uniquely identify the promoted
	// video.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdTag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsPromotedItem) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsPromotedItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsRecommendation: Information that identifies the
// recommended resource.
type ActivityContentDetailsRecommendation struct {
	// Reason: The reason that the resource is recommended to the user.
	//
	// Possible values:
	//   "unspecified"
	//   "videoFavorited"
	//   "videoLiked"
	//   "videoWatched"
	Reason string `json:"reason,omitempty"`

	// ResourceId: The resourceId object contains information that
	// identifies the recommended resource.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// SeedResourceId: The seedResourceId object contains information about
	// the resource that caused the recommendation.
	SeedResourceId *ResourceId `json:"seedResourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Reason") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsRecommendation) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsRecommendation
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsSocial: Details about a social network post.
type ActivityContentDetailsSocial struct {
	// Author: The author of the social network post.
	Author string `json:"author,omitempty"`

	// ImageUrl: An image of the post's author.
	ImageUrl string `json:"imageUrl,omitempty"`

	// ReferenceUrl: The URL of the social network post.
	ReferenceUrl string `json:"referenceUrl,omitempty"`

	// ResourceId: The resourceId object encapsulates information that
	// identifies the resource associated with a social network post.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// Type: The name of the social network.
	//
	// Possible values:
	//   "facebook"
	//   "googlePlus"
	//   "twitter"
	//   "unspecified"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Author") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsSocial) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsSocial
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsSubscription: Information about a channel that
// a user subscribed to.
type ActivityContentDetailsSubscription struct {
	// ResourceId: The resourceId object contains information that
	// identifies the resource that the user subscribed to.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsSubscription) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsSubscription
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityContentDetailsUpload: Information about the uploaded video.
type ActivityContentDetailsUpload struct {
	// VideoId: The ID that YouTube uses to uniquely identify the uploaded
	// video.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "VideoId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityContentDetailsUpload) MarshalJSON() ([]byte, error) {
	type noMethod ActivityContentDetailsUpload
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ActivityListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of activities, or events, that match the request
	// criteria.
	Items []*Activity `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#activityListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *ActivityListResponse) MarshalJSON() ([]byte, error) {
	type noMethod ActivityListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivitySnippet: Basic details about an activity, including title,
// description, thumbnails, activity type and group.
type ActivitySnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// associated with the activity.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: Channel title for the channel responsible for this
	// activity
	ChannelTitle string `json:"channelTitle,omitempty"`

	// Description: The description of the resource primarily associated
	// with the activity.
	Description string `json:"description,omitempty"`

	// GroupId: The group ID associated with the activity. A group ID
	// identifies user events that are associated with the same user and
	// resource. For example, if a user rates a video and marks the same
	// video as a favorite, the entries for those events would have the same
	// group ID in the user's activity feed. In your user interface, you can
	// avoid repetition by grouping events with the same groupId value.
	GroupId string `json:"groupId,omitempty"`

	// PublishedAt: The date and time that the video was uploaded. The value
	// is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the resource
	// that is primarily associated with the activity. For each object in
	// the map, the key is the name of the thumbnail image, and the value is
	// an object that contains other information about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The title of the resource primarily associated with the
	// activity.
	Title string `json:"title,omitempty"`

	// Type: The type of activity that the resource describes.
	//
	// Possible values:
	//   "bulletin"
	//   "channelItem"
	//   "comment"
	//   "favorite"
	//   "like"
	//   "playlistItem"
	//   "promotedItem"
	//   "recommendation"
	//   "social"
	//   "subscription"
	//   "upload"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivitySnippet) MarshalJSON() ([]byte, error) {
	type noMethod ActivitySnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Caption: A caption resource represents a YouTube caption track. A
// caption track is associated with exactly one YouTube video.
type Caption struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the caption track.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#caption".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the caption.
	Snippet *CaptionSnippet `json:"snippet,omitempty"`

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

func (s *Caption) MarshalJSON() ([]byte, error) {
	type noMethod Caption
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CaptionListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of captions that match the request criteria.
	Items []*Caption `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#captionListResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *CaptionListResponse) MarshalJSON() ([]byte, error) {
	type noMethod CaptionListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CaptionSnippet: Basic details about a caption track, such as its
// language and name.
type CaptionSnippet struct {
	// AudioTrackType: The type of audio track associated with the caption
	// track.
	//
	// Possible values:
	//   "commentary"
	//   "descriptive"
	//   "primary"
	//   "unknown"
	AudioTrackType string `json:"audioTrackType,omitempty"`

	// FailureReason: The reason that YouTube failed to process the caption
	// track. This property is only present if the state property's value is
	// failed.
	//
	// Possible values:
	//   "processingFailed"
	//   "unknownFormat"
	//   "unsupportedFormat"
	FailureReason string `json:"failureReason,omitempty"`

	// IsAutoSynced: Indicates whether YouTube synchronized the caption
	// track to the audio track in the video. The value will be true if a
	// sync was explicitly requested when the caption track was uploaded.
	// For example, when calling the captions.insert or captions.update
	// methods, you can set the sync parameter to true to instruct YouTube
	// to sync the uploaded track to the video. If the value is false,
	// YouTube uses the time codes in the uploaded caption track to
	// determine when to display captions.
	IsAutoSynced bool `json:"isAutoSynced,omitempty"`

	// IsCC: Indicates whether the track contains closed captions for the
	// deaf and hard of hearing. The default value is false.
	IsCC bool `json:"isCC,omitempty"`

	// IsDraft: Indicates whether the caption track is a draft. If the value
	// is true, then the track is not publicly visible. The default value is
	// false.
	IsDraft bool `json:"isDraft,omitempty"`

	// IsEasyReader: Indicates whether caption track is formatted for "easy
	// reader," meaning it is at a third-grade level for language learners.
	// The default value is false.
	IsEasyReader bool `json:"isEasyReader,omitempty"`

	// IsLarge: Indicates whether the caption track uses large text for the
	// vision-impaired. The default value is false.
	IsLarge bool `json:"isLarge,omitempty"`

	// Language: The language of the caption track. The property value is a
	// BCP-47 language tag.
	Language string `json:"language,omitempty"`

	// LastUpdated: The date and time when the caption track was last
	// updated. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	LastUpdated string `json:"lastUpdated,omitempty"`

	// Name: The name of the caption track. The name is intended to be
	// visible to the user as an option during playback.
	Name string `json:"name,omitempty"`

	// Status: The caption track's status.
	//
	// Possible values:
	//   "failed"
	//   "serving"
	//   "syncing"
	Status string `json:"status,omitempty"`

	// TrackKind: The caption track's type.
	//
	// Possible values:
	//   "ASR"
	//   "forced"
	//   "standard"
	TrackKind string `json:"trackKind,omitempty"`

	// VideoId: The ID that YouTube uses to uniquely identify the video
	// associated with the caption track.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AudioTrackType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CaptionSnippet) MarshalJSON() ([]byte, error) {
	type noMethod CaptionSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CdnSettings: Brief description of the live stream cdn settings.
type CdnSettings struct {
	// Format: The format of the video stream that you are sending to
	// Youtube.
	Format string `json:"format,omitempty"`

	// IngestionInfo: The ingestionInfo object contains information that
	// YouTube provides that you need to transmit your RTMP or HTTP stream
	// to YouTube.
	IngestionInfo *IngestionInfo `json:"ingestionInfo,omitempty"`

	// IngestionType: The method or protocol used to transmit the video
	// stream.
	//
	// Possible values:
	//   "dash"
	//   "rtmp"
	IngestionType string `json:"ingestionType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Format") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CdnSettings) MarshalJSON() ([]byte, error) {
	type noMethod CdnSettings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Channel: A channel resource contains information about a YouTube
// channel.
type Channel struct {
	// AuditDetails: The auditionDetails object encapsulates channel data
	// that is relevant for YouTube Partners during the audition process.
	AuditDetails *ChannelAuditDetails `json:"auditDetails,omitempty"`

	// BrandingSettings: The brandingSettings object encapsulates
	// information about the branding of the channel.
	BrandingSettings *ChannelBrandingSettings `json:"brandingSettings,omitempty"`

	// ContentDetails: The contentDetails object encapsulates information
	// about the channel's content.
	ContentDetails *ChannelContentDetails `json:"contentDetails,omitempty"`

	// ContentOwnerDetails: The contentOwnerDetails object encapsulates
	// channel data that is relevant for YouTube Partners linked with the
	// channel.
	ContentOwnerDetails *ChannelContentOwnerDetails `json:"contentOwnerDetails,omitempty"`

	// ConversionPings: The conversionPings object encapsulates information
	// about conversion pings that need to be respected by the channel.
	ConversionPings *ChannelConversionPings `json:"conversionPings,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the channel.
	Id string `json:"id,omitempty"`

	// InvideoPromotion: The invideoPromotion object encapsulates
	// information about promotion campaign associated with the channel.
	InvideoPromotion *InvideoPromotion `json:"invideoPromotion,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#channel".
	Kind string `json:"kind,omitempty"`

	// Localizations: Localizations for different languages
	Localizations map[string]ChannelLocalization `json:"localizations,omitempty"`

	// Snippet: The snippet object contains basic details about the channel,
	// such as its title, description, and thumbnail images.
	Snippet *ChannelSnippet `json:"snippet,omitempty"`

	// Statistics: The statistics object encapsulates statistics for the
	// channel.
	Statistics *ChannelStatistics `json:"statistics,omitempty"`

	// Status: The status object encapsulates information about the privacy
	// status of the channel.
	Status *ChannelStatus `json:"status,omitempty"`

	// TopicDetails: The topicDetails object encapsulates information about
	// Freebase topics associated with the channel.
	TopicDetails *ChannelTopicDetails `json:"topicDetails,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AuditDetails") to
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

// ChannelAuditDetails: The auditDetails object encapsulates channel
// data that is relevant for YouTube Partners during the audit process.
type ChannelAuditDetails struct {
	// CommunityGuidelinesGoodStanding: Whether or not the channel respects
	// the community guidelines.
	CommunityGuidelinesGoodStanding bool `json:"communityGuidelinesGoodStanding,omitempty"`

	// ContentIdClaimsGoodStanding: Whether or not the channel has any
	// unresolved claims.
	ContentIdClaimsGoodStanding bool `json:"contentIdClaimsGoodStanding,omitempty"`

	// CopyrightStrikesGoodStanding: Whether or not the channel has any
	// copyright strikes.
	CopyrightStrikesGoodStanding bool `json:"copyrightStrikesGoodStanding,omitempty"`

	// OverallGoodStanding: Describes the general state of the channel. This
	// field will always show if there are any issues whatsoever with the
	// channel. Currently this field represents the result of the logical
	// and operation over the community guidelines good standing, the
	// copyright strikes good standing and the content ID claims good
	// standing, but this may change in the future.
	OverallGoodStanding bool `json:"overallGoodStanding,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CommunityGuidelinesGoodStanding") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelAuditDetails) MarshalJSON() ([]byte, error) {
	type noMethod ChannelAuditDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelBannerResource: A channel banner returned as the response to a
// channel_banner.insert call.
type ChannelBannerResource struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#channelBannerResource".
	Kind string `json:"kind,omitempty"`

	// Url: The URL of this banner image.
	Url string `json:"url,omitempty"`

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

func (s *ChannelBannerResource) MarshalJSON() ([]byte, error) {
	type noMethod ChannelBannerResource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelBrandingSettings: Branding properties of a YouTube channel.
type ChannelBrandingSettings struct {
	// Channel: Branding properties for the channel view.
	Channel *ChannelSettings `json:"channel,omitempty"`

	// Hints: Additional experimental branding properties.
	Hints []*PropertyValue `json:"hints,omitempty"`

	// Image: Branding properties for branding images.
	Image *ImageSettings `json:"image,omitempty"`

	// Watch: Branding properties for the watch page.
	Watch *WatchSettings `json:"watch,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Channel") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelBrandingSettings) MarshalJSON() ([]byte, error) {
	type noMethod ChannelBrandingSettings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelContentDetails: Details about the content of a channel.
type ChannelContentDetails struct {
	// GooglePlusUserId: The googlePlusUserId object identifies the Google+
	// profile ID associated with this channel.
	GooglePlusUserId string `json:"googlePlusUserId,omitempty"`

	RelatedPlaylists *ChannelContentDetailsRelatedPlaylists `json:"relatedPlaylists,omitempty"`

	// ForceSendFields is a list of field names (e.g. "GooglePlusUserId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod ChannelContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ChannelContentDetailsRelatedPlaylists struct {
	// Favorites: The ID of the playlist that contains the channel"s
	// favorite videos. Use the  playlistItems.insert and
	// playlistItems.delete to add or remove items from that list.
	Favorites string `json:"favorites,omitempty"`

	// Likes: The ID of the playlist that contains the channel"s liked
	// videos. Use the   playlistItems.insert and  playlistItems.delete to
	// add or remove items from that list.
	Likes string `json:"likes,omitempty"`

	// Uploads: The ID of the playlist that contains the channel"s uploaded
	// videos. Use the  videos.insert method to upload new videos and the
	// videos.delete method to delete previously uploaded videos.
	Uploads string `json:"uploads,omitempty"`

	// WatchHistory: The ID of the playlist that contains the channel"s
	// watch history. Use the  playlistItems.insert and
	// playlistItems.delete to add or remove items from that list.
	WatchHistory string `json:"watchHistory,omitempty"`

	// WatchLater: The ID of the playlist that contains the channel"s watch
	// later playlist. Use the playlistItems.insert and
	// playlistItems.delete to add or remove items from that list.
	WatchLater string `json:"watchLater,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Favorites") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelContentDetailsRelatedPlaylists) MarshalJSON() ([]byte, error) {
	type noMethod ChannelContentDetailsRelatedPlaylists
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelContentOwnerDetails: The contentOwnerDetails object
// encapsulates channel data that is relevant for YouTube Partners
// linked with the channel.
type ChannelContentOwnerDetails struct {
	// ContentOwner: The ID of the content owner linked to the channel.
	ContentOwner string `json:"contentOwner,omitempty"`

	// TimeLinked: The date and time of when the channel was linked to the
	// content owner. The value is specified in ISO 8601
	// (YYYY-MM-DDThh:mm:ss.sZ) format.
	TimeLinked string `json:"timeLinked,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ContentOwner") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelContentOwnerDetails) MarshalJSON() ([]byte, error) {
	type noMethod ChannelContentOwnerDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelConversionPing: Pings that the app shall fire (authenticated
// by biscotti cookie). Each ping has a context, in which the app must
// fire the ping, and a url identifying the ping.
type ChannelConversionPing struct {
	// Context: Defines the context of the ping.
	//
	// Possible values:
	//   "cview"
	//   "subscribe"
	//   "unsubscribe"
	Context string `json:"context,omitempty"`

	// ConversionUrl: The url (without the schema) that the player shall
	// send the ping to. It's at caller's descretion to decide which schema
	// to use (http vs https) Example of a returned url:
	// //googleads.g.doubleclick.net/pagead/
	// viewthroughconversion/962985656/?data=path%3DtHe_path%3Btype%3D
	// cview%3Butuid%3DGISQtTNGYqaYl4sKxoVvKA&labe=default The caller must
	// append biscotti authentication (ms param in case of mobile, for
	// example) to this ping.
	ConversionUrl string `json:"conversionUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Context") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelConversionPing) MarshalJSON() ([]byte, error) {
	type noMethod ChannelConversionPing
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelConversionPings: The conversionPings object encapsulates
// information about conversion pings that need to be respected by the
// channel.
type ChannelConversionPings struct {
	// Pings: Pings that the app shall fire (authenticated by biscotti
	// cookie). Each ping has a context, in which the app must fire the
	// ping, and a url identifying the ping.
	Pings []*ChannelConversionPing `json:"pings,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Pings") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelConversionPings) MarshalJSON() ([]byte, error) {
	type noMethod ChannelConversionPings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ChannelId struct {
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Value") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelId) MarshalJSON() ([]byte, error) {
	type noMethod ChannelId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ChannelListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of channels that match the request criteria.
	Items []*Channel `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#channelListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *ChannelListResponse) MarshalJSON() ([]byte, error) {
	type noMethod ChannelListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelLocalization: Channel localization setting
type ChannelLocalization struct {
	// Description: The localized strings for channel's description.
	Description string `json:"description,omitempty"`

	// Title: The localized strings for channel's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelLocalization) MarshalJSON() ([]byte, error) {
	type noMethod ChannelLocalization
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ChannelSection struct {
	// ContentDetails: The contentDetails object contains details about the
	// channel section content, such as a list of playlists or channels
	// featured in the section.
	ContentDetails *ChannelSectionContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the channel
	// section.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#channelSection".
	Kind string `json:"kind,omitempty"`

	// Localizations: Localizations for different languages
	Localizations map[string]ChannelSectionLocalization `json:"localizations,omitempty"`

	// Snippet: The snippet object contains basic details about the channel
	// section, such as its type, style and title.
	Snippet *ChannelSectionSnippet `json:"snippet,omitempty"`

	// Targeting: The targeting object contains basic targeting settings
	// about the channel section.
	Targeting *ChannelSectionTargeting `json:"targeting,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSection) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSection
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSectionContentDetails: Details about a channelsection,
// including playlists and channels.
type ChannelSectionContentDetails struct {
	// Channels: The channel ids for type multiple_channels.
	Channels []string `json:"channels,omitempty"`

	// Playlists: The playlist ids for type single_playlist and
	// multiple_playlists. For singlePlaylist, only one playlistId is
	// allowed.
	Playlists []string `json:"playlists,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Channels") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSectionContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSectionContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ChannelSectionListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of ChannelSections that match the request criteria.
	Items []*ChannelSection `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#channelSectionListResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *ChannelSectionListResponse) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSectionListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSectionLocalization: ChannelSection localization setting
type ChannelSectionLocalization struct {
	// Title: The localized strings for channel section's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Title") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSectionLocalization) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSectionLocalization
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSectionSnippet: Basic details about a channel section,
// including title, style and position.
type ChannelSectionSnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// that published the channel section.
	ChannelId string `json:"channelId,omitempty"`

	// DefaultLanguage: The language of the channel section's default title
	// and description.
	DefaultLanguage string `json:"defaultLanguage,omitempty"`

	// Localized: Localized title, read-only.
	Localized *ChannelSectionLocalization `json:"localized,omitempty"`

	// Position: The position of the channel section in the channel.
	Position *int64 `json:"position,omitempty"`

	// Style: The style of the channel section.
	//
	// Possible values:
	//   "channelsectionStyleUndefined"
	//   "horizontalRow"
	//   "verticalList"
	Style string `json:"style,omitempty"`

	// Title: The channel section's title for multiple_playlists and
	// multiple_channels.
	Title string `json:"title,omitempty"`

	// Type: The type of the channel section.
	//
	// Possible values:
	//   "allPlaylists"
	//   "channelsectionTypeUndefined"
	//   "completedEvents"
	//   "likedPlaylists"
	//   "likes"
	//   "liveEvents"
	//   "multipleChannels"
	//   "multiplePlaylists"
	//   "popularUploads"
	//   "postedPlaylists"
	//   "postedVideos"
	//   "recentActivity"
	//   "recentPosts"
	//   "recentUploads"
	//   "singlePlaylist"
	//   "subscriptions"
	//   "upcomingEvents"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSectionSnippet) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSectionSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSectionTargeting: ChannelSection targeting setting.
type ChannelSectionTargeting struct {
	// Countries: The country the channel section is targeting.
	Countries []string `json:"countries,omitempty"`

	// Languages: The language the channel section is targeting.
	Languages []string `json:"languages,omitempty"`

	// Regions: The region the channel section is targeting.
	Regions []string `json:"regions,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Countries") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSectionTargeting) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSectionTargeting
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSettings: Branding properties for the channel view.
type ChannelSettings struct {
	// Country: The country of the channel.
	Country string `json:"country,omitempty"`

	DefaultLanguage string `json:"defaultLanguage,omitempty"`

	// DefaultTab: Which content tab users should see when viewing the
	// channel.
	DefaultTab string `json:"defaultTab,omitempty"`

	// Description: Specifies the channel description.
	Description string `json:"description,omitempty"`

	// FeaturedChannelsTitle: Title for the featured channels tab.
	FeaturedChannelsTitle string `json:"featuredChannelsTitle,omitempty"`

	// FeaturedChannelsUrls: The list of featured channels.
	FeaturedChannelsUrls []string `json:"featuredChannelsUrls,omitempty"`

	// Keywords: Lists keywords associated with the channel,
	// comma-separated.
	Keywords string `json:"keywords,omitempty"`

	// ModerateComments: Whether user-submitted comments left on the channel
	// page need to be approved by the channel owner to be publicly visible.
	ModerateComments bool `json:"moderateComments,omitempty"`

	// ProfileColor: A prominent color that can be rendered on this channel
	// page.
	ProfileColor string `json:"profileColor,omitempty"`

	// ShowBrowseView: Whether the tab to browse the videos should be
	// displayed.
	ShowBrowseView bool `json:"showBrowseView,omitempty"`

	// ShowRelatedChannels: Whether related channels should be proposed.
	ShowRelatedChannels bool `json:"showRelatedChannels,omitempty"`

	// Title: Specifies the channel title.
	Title string `json:"title,omitempty"`

	// TrackingAnalyticsAccountId: The ID for a Google Analytics account to
	// track and measure traffic to the channels.
	TrackingAnalyticsAccountId string `json:"trackingAnalyticsAccountId,omitempty"`

	// UnsubscribedTrailer: The trailer of the channel, for users that are
	// not subscribers.
	UnsubscribedTrailer string `json:"unsubscribedTrailer,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Country") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSettings) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSettings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelSnippet: Basic details about a channel, including title,
// description and thumbnails.
type ChannelSnippet struct {
	// Country: The country of the channel.
	Country string `json:"country,omitempty"`

	// DefaultLanguage: The language of the channel's default title and
	// description.
	DefaultLanguage string `json:"defaultLanguage,omitempty"`

	// Description: The description of the channel.
	Description string `json:"description,omitempty"`

	// Localized: Localized title and description, read-only.
	Localized *ChannelLocalization `json:"localized,omitempty"`

	// PublishedAt: The date and time that the channel was created. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the channel.
	// For each object in the map, the key is the name of the thumbnail
	// image, and the value is an object that contains other information
	// about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The channel's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Country") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelSnippet) MarshalJSON() ([]byte, error) {
	type noMethod ChannelSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelStatistics: Statistics about a channel: number of subscribers,
// number of videos in the channel, etc.
type ChannelStatistics struct {
	// CommentCount: The number of comments for the channel.
	CommentCount uint64 `json:"commentCount,omitempty,string"`

	// HiddenSubscriberCount: Whether or not the number of subscribers is
	// shown for this user.
	HiddenSubscriberCount bool `json:"hiddenSubscriberCount,omitempty"`

	// SubscriberCount: The number of subscribers that the channel has.
	SubscriberCount uint64 `json:"subscriberCount,omitempty,string"`

	// VideoCount: The number of videos uploaded to the channel.
	VideoCount uint64 `json:"videoCount,omitempty,string"`

	// ViewCount: The number of times the channel has been viewed.
	ViewCount uint64 `json:"viewCount,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "CommentCount") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelStatistics) MarshalJSON() ([]byte, error) {
	type noMethod ChannelStatistics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelStatus: JSON template for the status part of a channel.
type ChannelStatus struct {
	// IsLinked: If true, then the user is linked to either a YouTube
	// username or G+ account. Otherwise, the user doesn't have a public
	// YouTube identity.
	IsLinked bool `json:"isLinked,omitempty"`

	// LongUploadsStatus: The long uploads status of this channel. See
	//
	// Possible values:
	//   "allowed"
	//   "disallowed"
	//   "eligible"
	//   "longUploadsUnspecified"
	LongUploadsStatus string `json:"longUploadsStatus,omitempty"`

	// PrivacyStatus: Privacy status of the channel.
	//
	// Possible values:
	//   "private"
	//   "public"
	//   "unlisted"
	PrivacyStatus string `json:"privacyStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "IsLinked") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelStatus) MarshalJSON() ([]byte, error) {
	type noMethod ChannelStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChannelTopicDetails: Freebase topic information related to the
// channel.
type ChannelTopicDetails struct {
	// TopicIds: A list of Freebase topic IDs associated with the channel.
	// You can retrieve information about each topic using the Freebase
	// Topic API.
	TopicIds []string `json:"topicIds,omitempty"`

	// ForceSendFields is a list of field names (e.g. "TopicIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChannelTopicDetails) MarshalJSON() ([]byte, error) {
	type noMethod ChannelTopicDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Comment: A comment represents a single YouTube comment.
type Comment struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the comment.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#comment".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the comment.
	Snippet *CommentSnippet `json:"snippet,omitempty"`

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

func (s *Comment) MarshalJSON() ([]byte, error) {
	type noMethod Comment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CommentListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of comments that match the request criteria.
	Items []*Comment `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#commentListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *CommentListResponse) MarshalJSON() ([]byte, error) {
	type noMethod CommentListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentSnippet: Basic details about a comment, such as its author and
// text.
type CommentSnippet struct {
	// AuthorChannelId: The id of the author's YouTube channel, if any.
	AuthorChannelId *ChannelId `json:"authorChannelId,omitempty"`

	// AuthorChannelUrl: Link to the author's YouTube channel, if any.
	AuthorChannelUrl string `json:"authorChannelUrl,omitempty"`

	// AuthorDisplayName: The name of the user who posted the comment.
	AuthorDisplayName string `json:"authorDisplayName,omitempty"`

	// AuthorGoogleplusProfileUrl: Link to the author's Google+ profile, if
	// any.
	AuthorGoogleplusProfileUrl string `json:"authorGoogleplusProfileUrl,omitempty"`

	// AuthorProfileImageUrl: The URL for the avatar of the user who posted
	// the comment.
	AuthorProfileImageUrl string `json:"authorProfileImageUrl,omitempty"`

	// CanRate: Whether the current viewer can rate this comment.
	CanRate bool `json:"canRate,omitempty"`

	// ChannelId: The id of the corresponding YouTube channel. In case of a
	// channel comment this is the channel the comment refers to. In case of
	// a video comment it's the video's channel.
	ChannelId string `json:"channelId,omitempty"`

	// LikeCount: The total number of likes this comment has received.
	LikeCount int64 `json:"likeCount,omitempty"`

	// ModerationStatus: The comment's moderation status. Will not be set if
	// the comments were requested through the id filter.
	//
	// Possible values:
	//   "heldForReview"
	//   "likelySpam"
	//   "published"
	//   "rejected"
	ModerationStatus string `json:"moderationStatus,omitempty"`

	// ParentId: The unique id of the parent comment, only set for replies.
	ParentId string `json:"parentId,omitempty"`

	// PublishedAt: The date and time when the comment was orignally
	// published. The value is specified in ISO 8601
	// (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// TextDisplay: The comment's text. The format is either plain text or
	// HTML dependent on what has been requested. Even the plain text
	// representation may differ from the text originally posted in that it
	// may replace video links with video titles etc.
	TextDisplay string `json:"textDisplay,omitempty"`

	// TextOriginal: The comment's original raw text as initially posted or
	// last updated. The original text will only be returned if it is
	// accessible to the viewer, which is only guaranteed if the viewer is
	// the comment's author.
	TextOriginal string `json:"textOriginal,omitempty"`

	// UpdatedAt: The date and time when was last updated . The value is
	// specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	UpdatedAt string `json:"updatedAt,omitempty"`

	// VideoId: The ID of the video the comment refers to, if any.
	VideoId string `json:"videoId,omitempty"`

	// ViewerRating: The rating the viewer has given to this comment. For
	// the time being this will never return RATE_TYPE_DISLIKE and instead
	// return RATE_TYPE_NONE. This may change in the future.
	//
	// Possible values:
	//   "dislike"
	//   "like"
	//   "none"
	//   "unspecified"
	ViewerRating string `json:"viewerRating,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AuthorChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentSnippet) MarshalJSON() ([]byte, error) {
	type noMethod CommentSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentThread: A comment thread represents information that applies
// to a top level comment and all its replies. It can also include the
// top level comment itself and some of the replies.
type CommentThread struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the comment thread.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#commentThread".
	Kind string `json:"kind,omitempty"`

	// Replies: The replies object contains a limited number of replies (if
	// any) to the top level comment found in the snippet.
	Replies *CommentThreadReplies `json:"replies,omitempty"`

	// Snippet: The snippet object contains basic details about the comment
	// thread and also the top level comment.
	Snippet *CommentThreadSnippet `json:"snippet,omitempty"`

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

func (s *CommentThread) MarshalJSON() ([]byte, error) {
	type noMethod CommentThread
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CommentThreadListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of comment threads that match the request criteria.
	Items []*CommentThread `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#commentThreadListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *CommentThreadListResponse) MarshalJSON() ([]byte, error) {
	type noMethod CommentThreadListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentThreadReplies: Comments written in (direct or indirect) reply
// to the top level comment.
type CommentThreadReplies struct {
	// Comments: A limited number of replies. Unless the number of replies
	// returned equals total_reply_count in the snippet the returned replies
	// are only a subset of the total number of replies.
	Comments []*Comment `json:"comments,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Comments") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentThreadReplies) MarshalJSON() ([]byte, error) {
	type noMethod CommentThreadReplies
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentThreadSnippet: Basic details about a comment thread.
type CommentThreadSnippet struct {
	// CanReply: Whether the current viewer of the thread can reply to it.
	// This is viewer specific - other viewers may see a different value for
	// this field.
	CanReply bool `json:"canReply,omitempty"`

	// ChannelId: The YouTube channel the comments in the thread refer to or
	// the channel with the video the comments refer to. If video_id isn't
	// set the comments refer to the channel itself.
	ChannelId string `json:"channelId,omitempty"`

	// IsPublic: Whether the thread (and therefore all its comments) is
	// visible to all YouTube users.
	IsPublic bool `json:"isPublic,omitempty"`

	// TopLevelComment: The top level comment of this thread.
	TopLevelComment *Comment `json:"topLevelComment,omitempty"`

	// TotalReplyCount: The total number of replies (not including the top
	// level comment).
	TotalReplyCount int64 `json:"totalReplyCount,omitempty"`

	// VideoId: The ID of the video the comments refer to, if any. No
	// video_id implies a channel discussion comment.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CanReply") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentThreadSnippet) MarshalJSON() ([]byte, error) {
	type noMethod CommentThreadSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ContentRating: Ratings schemes. The country-specific ratings are
// mostly for movies and shows. NEXT_ID: 66
type ContentRating struct {
	// AcbRating: The video's Australian Classification Board (ACB) or
	// Australian Communications and Media Authority (ACMA) rating. ACMA
	// ratings are used to classify children's television programming.
	//
	// Possible values:
	//   "acbC"
	//   "acbE"
	//   "acbG"
	//   "acbM"
	//   "acbMa15plus"
	//   "acbP"
	//   "acbPg"
	//   "acbR18plus"
	//   "acbUnrated"
	AcbRating string `json:"acbRating,omitempty"`

	// AgcomRating: The video's rating from Italy's Autorità per le
	// Garanzie nelle Comunicazioni (AGCOM).
	//
	// Possible values:
	//   "agcomT"
	//   "agcomUnrated"
	//   "agcomVm14"
	//   "agcomVm18"
	AgcomRating string `json:"agcomRating,omitempty"`

	// AnatelRating: The video's Anatel (Asociación Nacional de
	// Televisión) rating for Chilean television.
	//
	// Possible values:
	//   "anatelA"
	//   "anatelF"
	//   "anatelI"
	//   "anatelI10"
	//   "anatelI12"
	//   "anatelI7"
	//   "anatelR"
	//   "anatelUnrated"
	AnatelRating string `json:"anatelRating,omitempty"`

	// BbfcRating: The video's British Board of Film Classification (BBFC)
	// rating.
	//
	// Possible values:
	//   "bbfc12"
	//   "bbfc12a"
	//   "bbfc15"
	//   "bbfc18"
	//   "bbfcPg"
	//   "bbfcR18"
	//   "bbfcU"
	//   "bbfcUnrated"
	BbfcRating string `json:"bbfcRating,omitempty"`

	// BfvcRating: The video's rating from Thailand's Board of Film and
	// Video Censors.
	//
	// Possible values:
	//   "bfvc13"
	//   "bfvc15"
	//   "bfvc18"
	//   "bfvc20"
	//   "bfvcB"
	//   "bfvcE"
	//   "bfvcG"
	//   "bfvcUnrated"
	BfvcRating string `json:"bfvcRating,omitempty"`

	// BmukkRating: The video's rating from the Austrian Board of Media
	// Classification (Bundesministerium für Unterricht, Kunst und Kultur).
	//
	// Possible values:
	//   "bmukk10"
	//   "bmukk12"
	//   "bmukk14"
	//   "bmukk16"
	//   "bmukk6"
	//   "bmukk8"
	//   "bmukkAa"
	//   "bmukkUnrated"
	BmukkRating string `json:"bmukkRating,omitempty"`

	// CatvRating: Rating system for Canadian TV - Canadian TV
	// Classification System The video's rating from the Canadian
	// Radio-Television and Telecommunications Commission (CRTC) for
	// Canadian English-language broadcasts. For more information, see the
	// Canadian Broadcast Standards Council website.
	//
	// Possible values:
	//   "catv14plus"
	//   "catv18plus"
	//   "catvC"
	//   "catvC8"
	//   "catvG"
	//   "catvPg"
	//   "catvUnrated"
	CatvRating string `json:"catvRating,omitempty"`

	// CatvfrRating: The video's rating from the Canadian Radio-Television
	// and Telecommunications Commission (CRTC) for Canadian French-language
	// broadcasts. For more information, see the Canadian Broadcast
	// Standards Council website.
	//
	// Possible values:
	//   "catvfr13plus"
	//   "catvfr16plus"
	//   "catvfr18plus"
	//   "catvfr8plus"
	//   "catvfrG"
	//   "catvfrUnrated"
	CatvfrRating string `json:"catvfrRating,omitempty"`

	// CbfcRating: The video's Central Board of Film Certification (CBFC -
	// India) rating.
	//
	// Possible values:
	//   "cbfcA"
	//   "cbfcS"
	//   "cbfcU"
	//   "cbfcUA"
	//   "cbfcUnrated"
	CbfcRating string `json:"cbfcRating,omitempty"`

	// CccRating: The video's Consejo de Calificación Cinematográfica
	// (Chile) rating.
	//
	// Possible values:
	//   "ccc14"
	//   "ccc18"
	//   "ccc18s"
	//   "ccc18v"
	//   "ccc6"
	//   "cccTe"
	//   "cccUnrated"
	CccRating string `json:"cccRating,omitempty"`

	// CceRating: The video's rating from Portugal's Comissão de
	// Classificação de Espect´culos.
	//
	// Possible values:
	//   "cceM12"
	//   "cceM16"
	//   "cceM18"
	//   "cceM4"
	//   "cceM6"
	//   "cceUnrated"
	CceRating string `json:"cceRating,omitempty"`

	// ChfilmRating: The video's rating in Switzerland.
	//
	// Possible values:
	//   "chfilm0"
	//   "chfilm12"
	//   "chfilm16"
	//   "chfilm18"
	//   "chfilm6"
	//   "chfilmUnrated"
	ChfilmRating string `json:"chfilmRating,omitempty"`

	// ChvrsRating: The video's Canadian Home Video Rating System (CHVRS)
	// rating.
	//
	// Possible values:
	//   "chvrs14a"
	//   "chvrs18a"
	//   "chvrsE"
	//   "chvrsG"
	//   "chvrsPg"
	//   "chvrsR"
	//   "chvrsUnrated"
	ChvrsRating string `json:"chvrsRating,omitempty"`

	// CicfRating: The video's rating from the Commission de Contrôle des
	// Films (Belgium).
	//
	// Possible values:
	//   "cicfE"
	//   "cicfKntEna"
	//   "cicfKtEa"
	//   "cicfUnrated"
	CicfRating string `json:"cicfRating,omitempty"`

	// CnaRating: The video's rating from Romania's CONSILIUL NATIONAL AL
	// AUDIOVIZUALULUI (CNA).
	//
	// Possible values:
	//   "cna12"
	//   "cna15"
	//   "cna18"
	//   "cna18plus"
	//   "cnaAp"
	//   "cnaUnrated"
	CnaRating string `json:"cnaRating,omitempty"`

	// CncRating: Rating system in France - Commission de classification
	// cinematographique
	//
	// Possible values:
	//   "cnc10"
	//   "cnc12"
	//   "cnc16"
	//   "cnc18"
	//   "cncE"
	//   "cncT"
	//   "cncUnrated"
	CncRating string `json:"cncRating,omitempty"`

	// CsaRating: The video's rating from France's Conseil supérieur de
	// l?audiovisuel, which rates broadcast content.
	//
	// Possible values:
	//   "csa10"
	//   "csa12"
	//   "csa16"
	//   "csa18"
	//   "csaInterdiction"
	//   "csaT"
	//   "csaUnrated"
	CsaRating string `json:"csaRating,omitempty"`

	// CscfRating: The video's rating from Luxembourg's Commission de
	// surveillance de la classification des films (CSCF).
	//
	// Possible values:
	//   "cscf12"
	//   "cscf16"
	//   "cscf18"
	//   "cscf6"
	//   "cscf9"
	//   "cscfA"
	//   "cscfAl"
	//   "cscfUnrated"
	CscfRating string `json:"cscfRating,omitempty"`

	// CzfilmRating: The video's rating in the Czech Republic.
	//
	// Possible values:
	//   "czfilm12"
	//   "czfilm14"
	//   "czfilm18"
	//   "czfilmU"
	//   "czfilmUnrated"
	CzfilmRating string `json:"czfilmRating,omitempty"`

	// DjctqRating: The video's Departamento de Justiça, Classificação,
	// Qualificação e Títulos (DJCQT - Brazil) rating.
	//
	// Possible values:
	//   "djctq10"
	//   "djctq12"
	//   "djctq14"
	//   "djctq16"
	//   "djctq18"
	//   "djctqL"
	//   "djctqUnrated"
	DjctqRating string `json:"djctqRating,omitempty"`

	// DjctqRatingReasons: Reasons that explain why the video received its
	// DJCQT (Brazil) rating.
	//
	// Possible values:
	//   "djctqCriminalActs"
	//   "djctqDrugs"
	//   "djctqExplicitSex"
	//   "djctqExtremeViolence"
	//   "djctqIllegalDrugs"
	//   "djctqImpactingContent"
	//   "djctqInappropriateLanguage"
	//   "djctqLegalDrugs"
	//   "djctqNudity"
	//   "djctqSex"
	//   "djctqSexualContent"
	//   "djctqViolence"
	DjctqRatingReasons []string `json:"djctqRatingReasons,omitempty"`

	// EefilmRating: The video's rating in Estonia.
	//
	// Possible values:
	//   "eefilmK12"
	//   "eefilmK14"
	//   "eefilmK16"
	//   "eefilmK6"
	//   "eefilmL"
	//   "eefilmMs12"
	//   "eefilmMs6"
	//   "eefilmPere"
	//   "eefilmUnrated"
	EefilmRating string `json:"eefilmRating,omitempty"`

	// EgfilmRating: The video's rating in Egypt.
	//
	// Possible values:
	//   "egfilm18"
	//   "egfilmBn"
	//   "egfilmGn"
	//   "egfilmUnrated"
	EgfilmRating string `json:"egfilmRating,omitempty"`

	// EirinRating: The video's Eirin (映倫) rating. Eirin is the Japanese
	// rating system.
	//
	// Possible values:
	//   "eirinG"
	//   "eirinPg12"
	//   "eirinR15plus"
	//   "eirinR18plus"
	//   "eirinUnrated"
	EirinRating string `json:"eirinRating,omitempty"`

	// FcbmRating: The video's rating from Malaysia's Film Censorship Board.
	//
	// Possible values:
	//   "fcbm18"
	//   "fcbm18pa"
	//   "fcbm18pl"
	//   "fcbm18sg"
	//   "fcbm18sx"
	//   "fcbmP13"
	//   "fcbmPg13"
	//   "fcbmU"
	//   "fcbmUnrated"
	FcbmRating string `json:"fcbmRating,omitempty"`

	// FcoRating: The video's rating from Hong Kong's Office for Film,
	// Newspaper and Article Administration.
	//
	// Possible values:
	//   "fcoI"
	//   "fcoIi"
	//   "fcoIia"
	//   "fcoIib"
	//   "fcoIii"
	//   "fcoUnrated"
	FcoRating string `json:"fcoRating,omitempty"`

	// FmocRating: This property has been deprecated. Use the
	// contentDetails.contentRating.cncRating instead.
	//
	// Possible values:
	//   "fmoc10"
	//   "fmoc12"
	//   "fmoc16"
	//   "fmoc18"
	//   "fmocE"
	//   "fmocU"
	//   "fmocUnrated"
	FmocRating string `json:"fmocRating,omitempty"`

	// FpbRating: The video's rating from South Africa's Film and
	// Publication Board.
	//
	// Possible values:
	//   "fpb1012Pg"
	//   "fpb13"
	//   "fpb16"
	//   "fpb18"
	//   "fpb79Pg"
	//   "fpbA"
	//   "fpbPg"
	//   "fpbUnrated"
	//   "fpbX18"
	//   "fpbXx"
	FpbRating string `json:"fpbRating,omitempty"`

	// FskRating: The video's Freiwillige Selbstkontrolle der Filmwirtschaft
	// (FSK - Germany) rating.
	//
	// Possible values:
	//   "fsk0"
	//   "fsk12"
	//   "fsk16"
	//   "fsk18"
	//   "fsk6"
	//   "fskUnrated"
	FskRating string `json:"fskRating,omitempty"`

	// GrfilmRating: The video's rating in Greece.
	//
	// Possible values:
	//   "grfilmE"
	//   "grfilmK"
	//   "grfilmK13"
	//   "grfilmK17"
	//   "grfilmUnrated"
	GrfilmRating string `json:"grfilmRating,omitempty"`

	// IcaaRating: The video's Instituto de la Cinematografía y de las
	// Artes Audiovisuales (ICAA - Spain) rating.
	//
	// Possible values:
	//   "icaa12"
	//   "icaa13"
	//   "icaa16"
	//   "icaa18"
	//   "icaa7"
	//   "icaaApta"
	//   "icaaUnrated"
	//   "icaaX"
	IcaaRating string `json:"icaaRating,omitempty"`

	// IfcoRating: The video's Irish Film Classification Office (IFCO -
	// Ireland) rating. See the IFCO website for more information.
	//
	// Possible values:
	//   "ifco12"
	//   "ifco12a"
	//   "ifco15"
	//   "ifco15a"
	//   "ifco16"
	//   "ifco18"
	//   "ifcoG"
	//   "ifcoPg"
	//   "ifcoUnrated"
	IfcoRating string `json:"ifcoRating,omitempty"`

	// IlfilmRating: The video's rating in Israel.
	//
	// Possible values:
	//   "ilfilm12"
	//   "ilfilm16"
	//   "ilfilm18"
	//   "ilfilmAa"
	//   "ilfilmUnrated"
	IlfilmRating string `json:"ilfilmRating,omitempty"`

	// IncaaRating: The video's INCAA (Instituto Nacional de Cine y Artes
	// Audiovisuales - Argentina) rating.
	//
	// Possible values:
	//   "incaaAtp"
	//   "incaaC"
	//   "incaaSam13"
	//   "incaaSam16"
	//   "incaaSam18"
	//   "incaaUnrated"
	IncaaRating string `json:"incaaRating,omitempty"`

	// KfcbRating: The video's rating from the Kenya Film Classification
	// Board.
	//
	// Possible values:
	//   "kfcb16plus"
	//   "kfcbG"
	//   "kfcbPg"
	//   "kfcbR"
	//   "kfcbUnrated"
	KfcbRating string `json:"kfcbRating,omitempty"`

	// KijkwijzerRating: voor de Classificatie van Audiovisuele Media
	// (Netherlands).
	//
	// Possible values:
	//   "kijkwijzer12"
	//   "kijkwijzer16"
	//   "kijkwijzer18"
	//   "kijkwijzer6"
	//   "kijkwijzer9"
	//   "kijkwijzerAl"
	//   "kijkwijzerUnrated"
	KijkwijzerRating string `json:"kijkwijzerRating,omitempty"`

	// KmrbRating: The video's Korea Media Rating Board
	// (영상물등급위원회) rating. The KMRB rates videos in South
	// Korea.
	//
	// Possible values:
	//   "kmrb12plus"
	//   "kmrb15plus"
	//   "kmrbAll"
	//   "kmrbR"
	//   "kmrbTeenr"
	//   "kmrbUnrated"
	KmrbRating string `json:"kmrbRating,omitempty"`

	// LsfRating: The video's rating from Indonesia's Lembaga Sensor Film.
	//
	// Possible values:
	//   "lsf13"
	//   "lsf17"
	//   "lsf21"
	//   "lsfA"
	//   "lsfBo"
	//   "lsfD"
	//   "lsfR"
	//   "lsfSu"
	//   "lsfUnrated"
	LsfRating string `json:"lsfRating,omitempty"`

	// MccaaRating: The video's rating from Malta's Film Age-Classification
	// Board.
	//
	// Possible values:
	//   "mccaa12"
	//   "mccaa12a"
	//   "mccaa14"
	//   "mccaa15"
	//   "mccaa16"
	//   "mccaa18"
	//   "mccaaPg"
	//   "mccaaU"
	//   "mccaaUnrated"
	MccaaRating string `json:"mccaaRating,omitempty"`

	// MccypRating: The video's rating from the Danish Film Institute's (Det
	// Danske Filminstitut) Media Council for Children and Young People.
	//
	// Possible values:
	//   "mccyp11"
	//   "mccyp15"
	//   "mccyp7"
	//   "mccypA"
	//   "mccypUnrated"
	MccypRating string `json:"mccypRating,omitempty"`

	// MdaRating: The video's rating from Singapore's Media Development
	// Authority (MDA) and, specifically, it's Board of Film Censors (BFC).
	//
	// Possible values:
	//   "mdaG"
	//   "mdaM18"
	//   "mdaNc16"
	//   "mdaPg"
	//   "mdaPg13"
	//   "mdaR21"
	//   "mdaUnrated"
	MdaRating string `json:"mdaRating,omitempty"`

	// MedietilsynetRating: The video's rating from Medietilsynet, the
	// Norwegian Media Authority.
	//
	// Possible values:
	//   "medietilsynet11"
	//   "medietilsynet12"
	//   "medietilsynet15"
	//   "medietilsynet18"
	//   "medietilsynet6"
	//   "medietilsynet7"
	//   "medietilsynet9"
	//   "medietilsynetA"
	//   "medietilsynetUnrated"
	MedietilsynetRating string `json:"medietilsynetRating,omitempty"`

	// MekuRating: The video's rating from Finland's Kansallinen
	// Audiovisuaalinen Instituutti (National Audiovisual Institute).
	//
	// Possible values:
	//   "meku12"
	//   "meku16"
	//   "meku18"
	//   "meku7"
	//   "mekuS"
	//   "mekuUnrated"
	MekuRating string `json:"mekuRating,omitempty"`

	// MibacRating: The video's rating from the Ministero dei Beni e delle
	// Attività Culturali e del Turismo (Italy).
	//
	// Possible values:
	//   "mibacT"
	//   "mibacUnrated"
	//   "mibacVap"
	//   "mibacVm12"
	//   "mibacVm14"
	//   "mibacVm18"
	MibacRating string `json:"mibacRating,omitempty"`

	// MocRating: The video's Ministerio de Cultura (Colombia) rating.
	//
	// Possible values:
	//   "moc12"
	//   "moc15"
	//   "moc18"
	//   "moc7"
	//   "mocBanned"
	//   "mocE"
	//   "mocT"
	//   "mocUnrated"
	//   "mocX"
	MocRating string `json:"mocRating,omitempty"`

	// MoctwRating: The video's rating from Taiwan's Ministry of Culture
	// (文化部).
	//
	// Possible values:
	//   "moctwG"
	//   "moctwP"
	//   "moctwPg"
	//   "moctwR"
	//   "moctwUnrated"
	MoctwRating string `json:"moctwRating,omitempty"`

	// MpaaRating: The video's Motion Picture Association of America (MPAA)
	// rating.
	//
	// Possible values:
	//   "mpaaG"
	//   "mpaaNc17"
	//   "mpaaPg"
	//   "mpaaPg13"
	//   "mpaaR"
	//   "mpaaUnrated"
	MpaaRating string `json:"mpaaRating,omitempty"`

	// MtrcbRating: The video's rating from the Movie and Television Review
	// and Classification Board (Philippines).
	//
	// Possible values:
	//   "mtrcbG"
	//   "mtrcbPg"
	//   "mtrcbR13"
	//   "mtrcbR16"
	//   "mtrcbR18"
	//   "mtrcbUnrated"
	//   "mtrcbX"
	MtrcbRating string `json:"mtrcbRating,omitempty"`

	// NbcRating: The video's rating from the Maldives National Bureau of
	// Classification.
	//
	// Possible values:
	//   "nbc12plus"
	//   "nbc15plus"
	//   "nbc18plus"
	//   "nbc18plusr"
	//   "nbcG"
	//   "nbcPg"
	//   "nbcPu"
	//   "nbcUnrated"
	NbcRating string `json:"nbcRating,omitempty"`

	// NbcplRating: The video's rating in Poland.
	//
	// Possible values:
	//   "nbcpl18plus"
	//   "nbcplI"
	//   "nbcplIi"
	//   "nbcplIii"
	//   "nbcplIv"
	//   "nbcplUnrated"
	NbcplRating string `json:"nbcplRating,omitempty"`

	// NfrcRating: The video's rating from the Bulgarian National Film
	// Center.
	//
	// Possible values:
	//   "nfrcA"
	//   "nfrcB"
	//   "nfrcC"
	//   "nfrcD"
	//   "nfrcUnrated"
	//   "nfrcX"
	NfrcRating string `json:"nfrcRating,omitempty"`

	// NfvcbRating: The video's rating from Nigeria's National Film and
	// Video Censors Board.
	//
	// Possible values:
	//   "nfvcb12"
	//   "nfvcb12a"
	//   "nfvcb15"
	//   "nfvcb18"
	//   "nfvcbG"
	//   "nfvcbPg"
	//   "nfvcbRe"
	//   "nfvcbUnrated"
	NfvcbRating string `json:"nfvcbRating,omitempty"`

	// NkclvRating: The video's rating from the Nacionãlais Kino centrs
	// (National Film Centre of Latvia).
	//
	// Possible values:
	//   "nkclv12plus"
	//   "nkclv18plus"
	//   "nkclv7plus"
	//   "nkclvU"
	//   "nkclvUnrated"
	NkclvRating string `json:"nkclvRating,omitempty"`

	// OflcRating: The video's Office of Film and Literature Classification
	// (OFLC - New Zealand) rating.
	//
	// Possible values:
	//   "oflcG"
	//   "oflcM"
	//   "oflcPg"
	//   "oflcR13"
	//   "oflcR15"
	//   "oflcR16"
	//   "oflcR18"
	//   "oflcRp13"
	//   "oflcRp16"
	//   "oflcUnrated"
	OflcRating string `json:"oflcRating,omitempty"`

	// PefilmRating: The video's rating in Peru.
	//
	// Possible values:
	//   "pefilm14"
	//   "pefilm18"
	//   "pefilmPg"
	//   "pefilmPt"
	//   "pefilmUnrated"
	PefilmRating string `json:"pefilmRating,omitempty"`

	// RcnofRating: The video's rating from the Hungarian Nemzeti Filmiroda,
	// the Rating Committee of the National Office of Film.
	//
	// Possible values:
	//   "rcnofI"
	//   "rcnofIi"
	//   "rcnofIii"
	//   "rcnofIv"
	//   "rcnofUnrated"
	//   "rcnofV"
	//   "rcnofVi"
	RcnofRating string `json:"rcnofRating,omitempty"`

	// ResorteviolenciaRating: The video's rating in Venezuela.
	//
	// Possible values:
	//   "resorteviolenciaA"
	//   "resorteviolenciaB"
	//   "resorteviolenciaC"
	//   "resorteviolenciaD"
	//   "resorteviolenciaE"
	//   "resorteviolenciaUnrated"
	ResorteviolenciaRating string `json:"resorteviolenciaRating,omitempty"`

	// RtcRating: The video's General Directorate of Radio, Television and
	// Cinematography (Mexico) rating.
	//
	// Possible values:
	//   "rtcA"
	//   "rtcAa"
	//   "rtcB"
	//   "rtcB15"
	//   "rtcC"
	//   "rtcD"
	//   "rtcUnrated"
	RtcRating string `json:"rtcRating,omitempty"`

	// RteRating: The video's rating from Ireland's Raidió Teilifís
	// Éireann.
	//
	// Possible values:
	//   "rteCh"
	//   "rteGa"
	//   "rteMa"
	//   "rtePs"
	//   "rteUnrated"
	RteRating string `json:"rteRating,omitempty"`

	// RussiaRating: The video's National Film Registry of the Russian
	// Federation (MKRF - Russia) rating.
	//
	// Possible values:
	//   "russia0"
	//   "russia12"
	//   "russia16"
	//   "russia18"
	//   "russia6"
	//   "russiaUnrated"
	RussiaRating string `json:"russiaRating,omitempty"`

	// SkfilmRating: The video's rating in Slovakia.
	//
	// Possible values:
	//   "skfilmG"
	//   "skfilmP2"
	//   "skfilmP5"
	//   "skfilmP8"
	//   "skfilmUnrated"
	SkfilmRating string `json:"skfilmRating,omitempty"`

	// SmaisRating: The video's rating in Iceland.
	//
	// Possible values:
	//   "smais12"
	//   "smais14"
	//   "smais16"
	//   "smais18"
	//   "smais7"
	//   "smaisL"
	//   "smaisUnrated"
	SmaisRating string `json:"smaisRating,omitempty"`

	// SmsaRating: The video's rating from Statens medieråd (Sweden's
	// National Media Council).
	//
	// Possible values:
	//   "smsa11"
	//   "smsa15"
	//   "smsa7"
	//   "smsaA"
	//   "smsaUnrated"
	SmsaRating string `json:"smsaRating,omitempty"`

	// TvpgRating: The video's TV Parental Guidelines (TVPG) rating.
	//
	// Possible values:
	//   "pg14"
	//   "tvpgG"
	//   "tvpgMa"
	//   "tvpgPg"
	//   "tvpgUnrated"
	//   "tvpgY"
	//   "tvpgY7"
	//   "tvpgY7Fv"
	TvpgRating string `json:"tvpgRating,omitempty"`

	// YtRating: A rating that YouTube uses to identify age-restricted
	// content.
	//
	// Possible values:
	//   "ytAgeRestricted"
	YtRating string `json:"ytRating,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AcbRating") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ContentRating) MarshalJSON() ([]byte, error) {
	type noMethod ContentRating
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GeoPoint: Geographical coordinates of a point, in WGS84.
type GeoPoint struct {
	// Altitude: Altitude above the reference ellipsoid, in meters.
	Altitude float64 `json:"altitude,omitempty"`

	// Latitude: Latitude in degrees.
	Latitude float64 `json:"latitude,omitempty"`

	// Longitude: Longitude in degrees.
	Longitude float64 `json:"longitude,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Altitude") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GeoPoint) MarshalJSON() ([]byte, error) {
	type noMethod GeoPoint
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GuideCategory: A guideCategory resource identifies a category that
// YouTube algorithmically assigns based on a channel's content or other
// indicators, such as the channel's popularity. The list is similar to
// video categories, with the difference being that a video's uploader
// can assign a video category but only YouTube can assign a channel
// category.
type GuideCategory struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the guide category.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#guideCategory".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the
	// category, such as its title.
	Snippet *GuideCategorySnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GuideCategory) MarshalJSON() ([]byte, error) {
	type noMethod GuideCategory
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GuideCategoryListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of categories that can be associated with YouTube
	// channels. In this map, the category ID is the map key, and its value
	// is the corresponding guideCategory resource.
	Items []*GuideCategory `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#guideCategoryListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *GuideCategoryListResponse) MarshalJSON() ([]byte, error) {
	type noMethod GuideCategoryListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GuideCategorySnippet: Basic details about a guide category.
type GuideCategorySnippet struct {
	ChannelId string `json:"channelId,omitempty"`

	// Title: Description of the guide category.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GuideCategorySnippet) MarshalJSON() ([]byte, error) {
	type noMethod GuideCategorySnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// I18nLanguage: An i18nLanguage resource identifies a UI language
// currently supported by YouTube.
type I18nLanguage struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the i18n language.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#i18nLanguage".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the i18n
	// language, such as language code and human-readable name.
	Snippet *I18nLanguageSnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *I18nLanguage) MarshalJSON() ([]byte, error) {
	type noMethod I18nLanguage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type I18nLanguageListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of supported i18n languages. In this map, the i18n
	// language ID is the map key, and its value is the corresponding
	// i18nLanguage resource.
	Items []*I18nLanguage `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#i18nLanguageListResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *I18nLanguageListResponse) MarshalJSON() ([]byte, error) {
	type noMethod I18nLanguageListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// I18nLanguageSnippet: Basic details about an i18n language, such as
// language code and human-readable name.
type I18nLanguageSnippet struct {
	// Hl: A short BCP-47 code that uniquely identifies a language.
	Hl string `json:"hl,omitempty"`

	// Name: The human-readable name of the language in the language itself.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Hl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *I18nLanguageSnippet) MarshalJSON() ([]byte, error) {
	type noMethod I18nLanguageSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// I18nRegion: A i18nRegion resource identifies a region where YouTube
// is available.
type I18nRegion struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the i18n region.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#i18nRegion".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the i18n
	// region, such as region code and human-readable name.
	Snippet *I18nRegionSnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *I18nRegion) MarshalJSON() ([]byte, error) {
	type noMethod I18nRegion
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type I18nRegionListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of regions where YouTube is available. In this map, the
	// i18n region ID is the map key, and its value is the corresponding
	// i18nRegion resource.
	Items []*I18nRegion `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#i18nRegionListResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *I18nRegionListResponse) MarshalJSON() ([]byte, error) {
	type noMethod I18nRegionListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// I18nRegionSnippet: Basic details about an i18n region, such as region
// code and human-readable name.
type I18nRegionSnippet struct {
	// Gl: The region code as a 2-letter ISO country code.
	Gl string `json:"gl,omitempty"`

	// Name: The human-readable name of the region.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Gl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *I18nRegionSnippet) MarshalJSON() ([]byte, error) {
	type noMethod I18nRegionSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImageSettings: Branding properties for images associated with the
// channel.
type ImageSettings struct {
	// BackgroundImageUrl: The URL for the background image shown on the
	// video watch page. The image should be 1200px by 615px, with a maximum
	// file size of 128k.
	BackgroundImageUrl *LocalizedProperty `json:"backgroundImageUrl,omitempty"`

	// BannerExternalUrl: This is used only in update requests; if it's set,
	// we use this URL to generate all of the above banner URLs.
	BannerExternalUrl string `json:"bannerExternalUrl,omitempty"`

	// BannerImageUrl: Banner image. Desktop size (1060x175).
	BannerImageUrl string `json:"bannerImageUrl,omitempty"`

	// BannerMobileExtraHdImageUrl: Banner image. Mobile size high
	// resolution (1440x395).
	BannerMobileExtraHdImageUrl string `json:"bannerMobileExtraHdImageUrl,omitempty"`

	// BannerMobileHdImageUrl: Banner image. Mobile size high resolution
	// (1280x360).
	BannerMobileHdImageUrl string `json:"bannerMobileHdImageUrl,omitempty"`

	// BannerMobileImageUrl: Banner image. Mobile size (640x175).
	BannerMobileImageUrl string `json:"bannerMobileImageUrl,omitempty"`

	// BannerMobileLowImageUrl: Banner image. Mobile size low resolution
	// (320x88).
	BannerMobileLowImageUrl string `json:"bannerMobileLowImageUrl,omitempty"`

	// BannerMobileMediumHdImageUrl: Banner image. Mobile size medium/high
	// resolution (960x263).
	BannerMobileMediumHdImageUrl string `json:"bannerMobileMediumHdImageUrl,omitempty"`

	// BannerTabletExtraHdImageUrl: Banner image. Tablet size extra high
	// resolution (2560x424).
	BannerTabletExtraHdImageUrl string `json:"bannerTabletExtraHdImageUrl,omitempty"`

	// BannerTabletHdImageUrl: Banner image. Tablet size high resolution
	// (2276x377).
	BannerTabletHdImageUrl string `json:"bannerTabletHdImageUrl,omitempty"`

	// BannerTabletImageUrl: Banner image. Tablet size (1707x283).
	BannerTabletImageUrl string `json:"bannerTabletImageUrl,omitempty"`

	// BannerTabletLowImageUrl: Banner image. Tablet size low resolution
	// (1138x188).
	BannerTabletLowImageUrl string `json:"bannerTabletLowImageUrl,omitempty"`

	// BannerTvHighImageUrl: Banner image. TV size high resolution
	// (1920x1080).
	BannerTvHighImageUrl string `json:"bannerTvHighImageUrl,omitempty"`

	// BannerTvImageUrl: Banner image. TV size extra high resolution
	// (2120x1192).
	BannerTvImageUrl string `json:"bannerTvImageUrl,omitempty"`

	// BannerTvLowImageUrl: Banner image. TV size low resolution (854x480).
	BannerTvLowImageUrl string `json:"bannerTvLowImageUrl,omitempty"`

	// BannerTvMediumImageUrl: Banner image. TV size medium resolution
	// (1280x720).
	BannerTvMediumImageUrl string `json:"bannerTvMediumImageUrl,omitempty"`

	// LargeBrandedBannerImageImapScript: The image map script for the large
	// banner image.
	LargeBrandedBannerImageImapScript *LocalizedProperty `json:"largeBrandedBannerImageImapScript,omitempty"`

	// LargeBrandedBannerImageUrl: The URL for the 854px by 70px image that
	// appears below the video player in the expanded video view of the
	// video watch page.
	LargeBrandedBannerImageUrl *LocalizedProperty `json:"largeBrandedBannerImageUrl,omitempty"`

	// SmallBrandedBannerImageImapScript: The image map script for the small
	// banner image.
	SmallBrandedBannerImageImapScript *LocalizedProperty `json:"smallBrandedBannerImageImapScript,omitempty"`

	// SmallBrandedBannerImageUrl: The URL for the 640px by 70px banner
	// image that appears below the video player in the default view of the
	// video watch page.
	SmallBrandedBannerImageUrl *LocalizedProperty `json:"smallBrandedBannerImageUrl,omitempty"`

	// TrackingImageUrl: The URL for a 1px by 1px tracking pixel that can be
	// used to collect statistics for views of the channel or video pages.
	TrackingImageUrl string `json:"trackingImageUrl,omitempty"`

	// WatchIconImageUrl: The URL for the image that appears above the
	// top-left corner of the video player. This is a 25-pixel-high image
	// with a flexible width that cannot exceed 170 pixels.
	WatchIconImageUrl string `json:"watchIconImageUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BackgroundImageUrl")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImageSettings) MarshalJSON() ([]byte, error) {
	type noMethod ImageSettings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// IngestionInfo: Describes information necessary for ingesting an RTMP
// or an HTTP stream.
type IngestionInfo struct {
	// BackupIngestionAddress: The backup ingestion URL that you should use
	// to stream video to YouTube. You have the option of simultaneously
	// streaming the content that you are sending to the ingestionAddress to
	// this URL.
	BackupIngestionAddress string `json:"backupIngestionAddress,omitempty"`

	// IngestionAddress: The primary ingestion URL that you should use to
	// stream video to YouTube. You must stream video to this
	// URL.
	//
	// Depending on which application or tool you use to encode your video
	// stream, you may need to enter the stream URL and stream name
	// separately or you may need to concatenate them in the following
	// format:
	//
	// STREAM_URL/STREAM_NAME
	IngestionAddress string `json:"ingestionAddress,omitempty"`

	// StreamName: The HTTP or RTMP stream name that YouTube assigns to the
	// video stream.
	StreamName string `json:"streamName,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "BackupIngestionAddress") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *IngestionInfo) MarshalJSON() ([]byte, error) {
	type noMethod IngestionInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type InvideoBranding struct {
	ImageBytes string `json:"imageBytes,omitempty"`

	ImageUrl string `json:"imageUrl,omitempty"`

	Position *InvideoPosition `json:"position,omitempty"`

	TargetChannelId string `json:"targetChannelId,omitempty"`

	Timing *InvideoTiming `json:"timing,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ImageBytes") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InvideoBranding) MarshalJSON() ([]byte, error) {
	type noMethod InvideoBranding
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InvideoPosition: Describes the spatial position of a visual widget
// inside a video. It is a union of various position types, out of which
// only will be set one.
type InvideoPosition struct {
	// CornerPosition: Describes in which corner of the video the visual
	// widget will appear.
	//
	// Possible values:
	//   "bottomLeft"
	//   "bottomRight"
	//   "topLeft"
	//   "topRight"
	CornerPosition string `json:"cornerPosition,omitempty"`

	// Type: Defines the position type.
	//
	// Possible values:
	//   "corner"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CornerPosition") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InvideoPosition) MarshalJSON() ([]byte, error) {
	type noMethod InvideoPosition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InvideoPromotion: Describes an invideo promotion campaign consisting
// of multiple promoted items. A campaign belongs to a single
// channel_id.
type InvideoPromotion struct {
	// DefaultTiming: The default temporal position within the video where
	// the promoted item will be displayed. Can be overriden by more
	// specific timing in the item.
	DefaultTiming *InvideoTiming `json:"defaultTiming,omitempty"`

	// Items: List of promoted items in decreasing priority.
	Items []*PromotedItem `json:"items,omitempty"`

	// Position: The spatial position within the video where the promoted
	// item will be displayed.
	Position *InvideoPosition `json:"position,omitempty"`

	// UseSmartTiming: Indicates whether the channel's promotional campaign
	// uses "smart timing." This feature attempts to show promotions at a
	// point in the video when they are more likely to be clicked and less
	// likely to disrupt the viewing experience. This feature also picks up
	// a single promotion to show on each video.
	UseSmartTiming bool `json:"useSmartTiming,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DefaultTiming") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InvideoPromotion) MarshalJSON() ([]byte, error) {
	type noMethod InvideoPromotion
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InvideoTiming: Describes a temporal position of a visual widget
// inside a video.
type InvideoTiming struct {
	// DurationMs: Defines the duration in milliseconds for which the
	// promotion should be displayed. If missing, the client should use the
	// default.
	DurationMs uint64 `json:"durationMs,omitempty,string"`

	// OffsetMs: Defines the time at which the promotion will appear.
	// Depending on the value of type the value of the offsetMs field will
	// represent a time offset from the start or from the end of the video,
	// expressed in milliseconds.
	OffsetMs uint64 `json:"offsetMs,omitempty,string"`

	// Type: Describes a timing type. If the value is offsetFromStart, then
	// the offsetMs field represents an offset from the start of the video.
	// If the value is offsetFromEnd, then the offsetMs field represents an
	// offset from the end of the video.
	//
	// Possible values:
	//   "offsetFromEnd"
	//   "offsetFromStart"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DurationMs") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InvideoTiming) MarshalJSON() ([]byte, error) {
	type noMethod InvideoTiming
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LanguageTag struct {
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Value") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LanguageTag) MarshalJSON() ([]byte, error) {
	type noMethod LanguageTag
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveBroadcast: A liveBroadcast resource represents an event that will
// be streamed, via live video, on YouTube.
type LiveBroadcast struct {
	// ContentDetails: The contentDetails object contains information about
	// the event's video content, such as whether the content can be shown
	// in an embedded video player or if it will be archived and therefore
	// available for viewing after the event has concluded.
	ContentDetails *LiveBroadcastContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube assigns to uniquely identify the broadcast.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#liveBroadcast".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the event,
	// including its title, description, start time, and end time.
	Snippet *LiveBroadcastSnippet `json:"snippet,omitempty"`

	// Statistics: The statistics object contains info about the event's
	// current stats. These include concurrent viewers and total chat count.
	// Statistics can change (in either direction) during the lifetime of an
	// event. Statistics are only returned while the event is live.
	Statistics *LiveBroadcastStatistics `json:"statistics,omitempty"`

	// Status: The status object contains information about the event's
	// status.
	Status *LiveBroadcastStatus `json:"status,omitempty"`

	TopicDetails *LiveBroadcastTopicDetails `json:"topicDetails,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcast) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcast
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveBroadcastContentDetails: Detailed settings of a broadcast.
type LiveBroadcastContentDetails struct {
	// BoundStreamId: This value uniquely identifies the live stream bound
	// to the broadcast.
	BoundStreamId string `json:"boundStreamId,omitempty"`

	// EnableClosedCaptions: This setting indicates whether closed
	// captioning is enabled for this broadcast. The ingestion URL of the
	// closed captions is returned through the liveStreams API.
	EnableClosedCaptions bool `json:"enableClosedCaptions,omitempty"`

	// EnableContentEncryption: This setting indicates whether YouTube
	// should enable content encryption for the broadcast.
	EnableContentEncryption bool `json:"enableContentEncryption,omitempty"`

	// EnableDvr: This setting determines whether viewers can access DVR
	// controls while watching the video. DVR controls enable the viewer to
	// control the video playback experience by pausing, rewinding, or fast
	// forwarding content. The default value for this property is
	// true.
	//
	//
	//
	// Important: You must set the value to true and also set the
	// enableArchive property's value to true if you want to make playback
	// available immediately after the broadcast ends.
	EnableDvr bool `json:"enableDvr,omitempty"`

	// EnableEmbed: This setting indicates whether the broadcast video can
	// be played in an embedded player. If you choose to archive the video
	// (using the enableArchive property), this setting will also apply to
	// the archived video.
	EnableEmbed bool `json:"enableEmbed,omitempty"`

	EnableLowLatency bool `json:"enableLowLatency,omitempty"`

	// MonitorStream: The monitorStream object contains information about
	// the monitor stream, which the broadcaster can use to review the event
	// content before the broadcast stream is shown publicly.
	MonitorStream *MonitorStreamInfo `json:"monitorStream,omitempty"`

	// RecordFromStart: Automatically start recording after the event goes
	// live. The default value for this property is true.
	//
	//
	//
	// Important: You must also set the enableDvr property's value to true
	// if you want the playback to be available immediately after the
	// broadcast ends. If you set this property's value to true but do not
	// also set the enableDvr property to true, there may be a delay of
	// around one day before the archived video will be available for
	// playback.
	RecordFromStart bool `json:"recordFromStart,omitempty"`

	// StartWithSlate: This setting indicates whether the broadcast should
	// automatically begin with an in-stream slate when you update the
	// broadcast's status to live. After updating the status, you then need
	// to send a liveCuepoints.insert request that sets the cuepoint's
	// eventState to end to remove the in-stream slate and make your
	// broadcast stream visible to viewers.
	StartWithSlate bool `json:"startWithSlate,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BoundStreamId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of broadcasts that match the request criteria.
	Items []*LiveBroadcast `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#liveBroadcastListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *LiveBroadcastListResponse) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastSnippet struct {
	// ActualEndTime: The date and time that the broadcast actually ended.
	// This information is only available once the broadcast's state is
	// complete. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	ActualEndTime string `json:"actualEndTime,omitempty"`

	// ActualStartTime: The date and time that the broadcast actually
	// started. This information is only available once the broadcast's
	// state is live. The value is specified in ISO 8601
	// (YYYY-MM-DDThh:mm:ss.sZ) format.
	ActualStartTime string `json:"actualStartTime,omitempty"`

	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// that is publishing the broadcast.
	ChannelId string `json:"channelId,omitempty"`

	// Description: The broadcast's description. As with the title, you can
	// set this field by modifying the broadcast resource or by setting the
	// description field of the corresponding video resource.
	Description string `json:"description,omitempty"`

	IsDefaultBroadcast bool `json:"isDefaultBroadcast,omitempty"`

	// LiveChatId: The id of the live chat for this broadcast.
	LiveChatId string `json:"liveChatId,omitempty"`

	// PublishedAt: The date and time that the broadcast was added to
	// YouTube's live broadcast schedule. The value is specified in ISO 8601
	// (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// ScheduledEndTime: The date and time that the broadcast is scheduled
	// to end. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	ScheduledEndTime string `json:"scheduledEndTime,omitempty"`

	// ScheduledStartTime: The date and time that the broadcast is scheduled
	// to start. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	ScheduledStartTime string `json:"scheduledStartTime,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the broadcast.
	// For each nested object in this object, the key is the name of the
	// thumbnail image, and the value is an object that contains other
	// information about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The broadcast's title. Note that the broadcast represents
	// exactly one YouTube video. You can set this field by modifying the
	// broadcast resource or by setting the title field of the corresponding
	// video resource.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ActualEndTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastSnippet) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveBroadcastStatistics: Statistics about the live broadcast. These
// represent a snapshot of the values at the time of the request.
// Statistics are only returned for live broadcasts.
type LiveBroadcastStatistics struct {
	// ConcurrentViewers: The number of viewers currently watching the
	// broadcast. The property and its value will be present if the
	// broadcast has current viewers and the broadcast owner has not hidden
	// the viewcount for the video. Note that YouTube stops tracking the
	// number of concurrent viewers for a broadcast when the broadcast ends.
	// So, this property would not identify the number of viewers watching
	// an archived video of a live broadcast that already ended.
	ConcurrentViewers uint64 `json:"concurrentViewers,omitempty,string"`

	// TotalChatCount: The total number of live chat messages currently on
	// the broadcast. The property and its value will be present if the
	// broadcast is public, has the live chat feature enabled, and has at
	// least one message. Note that this field will not be filled after the
	// broadcast ends. So this property would not identify the number of
	// chat messages for an archived video of a completed live broadcast.
	TotalChatCount uint64 `json:"totalChatCount,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "ConcurrentViewers")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastStatistics) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastStatistics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastStatus struct {
	// LifeCycleStatus: The broadcast's status. The status can be updated
	// using the API's liveBroadcasts.transition method.
	//
	// Possible values:
	//   "abandoned"
	//   "complete"
	//   "completeStarting"
	//   "created"
	//   "live"
	//   "liveStarting"
	//   "ready"
	//   "reclaimed"
	//   "revoked"
	//   "testStarting"
	//   "testing"
	LifeCycleStatus string `json:"lifeCycleStatus,omitempty"`

	// LiveBroadcastPriority: Priority of the live broadcast event (internal
	// state).
	//
	// Possible values:
	//   "high"
	//   "low"
	//   "normal"
	LiveBroadcastPriority string `json:"liveBroadcastPriority,omitempty"`

	// PrivacyStatus: The broadcast's privacy status. Note that the
	// broadcast represents exactly one YouTube video, so the privacy
	// settings are identical to those supported for videos. In addition,
	// you can set this field by modifying the broadcast resource or by
	// setting the privacyStatus field of the corresponding video resource.
	//
	// Possible values:
	//   "private"
	//   "public"
	//   "unlisted"
	PrivacyStatus string `json:"privacyStatus,omitempty"`

	// RecordingStatus: The broadcast's recording status.
	//
	// Possible values:
	//   "notRecording"
	//   "recorded"
	//   "recording"
	RecordingStatus string `json:"recordingStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "LifeCycleStatus") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastStatus) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastTopic struct {
	// Snippet: Information about the topic matched.
	Snippet *LiveBroadcastTopicSnippet `json:"snippet,omitempty"`

	// Type: The type of the topic.
	//
	// Possible values:
	//   "videoGame"
	Type string `json:"type,omitempty"`

	// Unmatched: If this flag is set it means that we have not been able to
	// match the topic title and type provided to a known entity.
	Unmatched bool `json:"unmatched,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Snippet") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastTopic) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastTopic
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastTopicDetails struct {
	Topics []*LiveBroadcastTopic `json:"topics,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Topics") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastTopicDetails) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastTopicDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveBroadcastTopicSnippet struct {
	// Name: The name of the topic.
	Name string `json:"name,omitempty"`

	// ReleaseDate: The date at which the topic was released. Filled for
	// types: videoGame
	ReleaseDate string `json:"releaseDate,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Name") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveBroadcastTopicSnippet) MarshalJSON() ([]byte, error) {
	type noMethod LiveBroadcastTopicSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveStream: A live stream describes a live ingestion point.
type LiveStream struct {
	// Cdn: The cdn object defines the live stream's content delivery
	// network (CDN) settings. These settings provide details about the
	// manner in which you stream your content to YouTube.
	Cdn *CdnSettings `json:"cdn,omitempty"`

	// ContentDetails: The content_details object contains information about
	// the stream, including the closed captions ingestion URL.
	ContentDetails *LiveStreamContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube assigns to uniquely identify the stream.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#liveStream".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the stream,
	// including its channel, title, and description.
	Snippet *LiveStreamSnippet `json:"snippet,omitempty"`

	// Status: The status object contains information about live stream's
	// status.
	Status *LiveStreamStatus `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Cdn") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStream) MarshalJSON() ([]byte, error) {
	type noMethod LiveStream
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveStreamConfigurationIssue struct {
	// Description: The long-form description of the issue and how to
	// resolve it.
	Description string `json:"description,omitempty"`

	// Reason: The short-form reason for this issue.
	Reason string `json:"reason,omitempty"`

	// Severity: How severe this issue is to the stream.
	//
	// Possible values:
	//   "error"
	//   "info"
	//   "warning"
	Severity string `json:"severity,omitempty"`

	// Type: The kind of error happening.
	//
	// Possible values:
	//   "audioBitrateHigh"
	//   "audioBitrateLow"
	//   "audioBitrateMismatch"
	//   "audioCodec"
	//   "audioCodecMismatch"
	//   "audioSampleRate"
	//   "audioSampleRateMismatch"
	//   "audioStereoMismatch"
	//   "audioTooManyChannels"
	//   "badContainer"
	//   "bitrateHigh"
	//   "bitrateLow"
	//   "frameRateHigh"
	//   "framerateMismatch"
	//   "gopMismatch"
	//   "gopSizeLong"
	//   "gopSizeOver"
	//   "gopSizeShort"
	//   "interlacedVideo"
	//   "multipleAudioStreams"
	//   "multipleVideoStreams"
	//   "noAudioStream"
	//   "noVideoStream"
	//   "openGop"
	//   "resolutionMismatch"
	//   "videoBitrateMismatch"
	//   "videoCodec"
	//   "videoCodecMismatch"
	//   "videoIngestionStarved"
	//   "videoInterlaceMismatch"
	//   "videoProfileMismatch"
	//   "videoResolutionSuboptimal"
	//   "videoResolutionUnsupported"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStreamConfigurationIssue) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamConfigurationIssue
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveStreamContentDetails: Detailed settings of a stream.
type LiveStreamContentDetails struct {
	// ClosedCaptionsIngestionUrl: The ingestion URL where the closed
	// captions of this stream are sent.
	ClosedCaptionsIngestionUrl string `json:"closedCaptionsIngestionUrl,omitempty"`

	// IsReusable: Indicates whether the stream is reusable, which means
	// that it can be bound to multiple broadcasts. It is common for
	// broadcasters to reuse the same stream for many different broadcasts
	// if those broadcasts occur at different times.
	//
	// If you set this value to false, then the stream will not be reusable,
	// which means that it can only be bound to one broadcast. Non-reusable
	// streams differ from reusable streams in the following ways:
	// - A non-reusable stream can only be bound to one broadcast.
	// - A non-reusable stream might be deleted by an automated process
	// after the broadcast ends.
	// - The  liveStreams.list method does not list non-reusable streams if
	// you call the method and set the mine parameter to true. The only way
	// to use that method to retrieve the resource for a non-reusable stream
	// is to use the id parameter to identify the stream.
	IsReusable bool `json:"isReusable,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ClosedCaptionsIngestionUrl") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStreamContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveStreamHealthStatus struct {
	// ConfigurationIssues: The configurations issues on this stream
	ConfigurationIssues []*LiveStreamConfigurationIssue `json:"configurationIssues,omitempty"`

	// LastUpdateTimeSeconds: The last time this status was updated (in
	// seconds)
	LastUpdateTimeSeconds uint64 `json:"lastUpdateTimeSeconds,omitempty,string"`

	// Status: The status code of this stream
	//
	// Possible values:
	//   "bad"
	//   "good"
	//   "noData"
	//   "ok"
	//   "revoked"
	Status string `json:"status,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ConfigurationIssues")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStreamHealthStatus) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamHealthStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveStreamListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of live streams that match the request criteria.
	Items []*LiveStream `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#liveStreamListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *LiveStreamListResponse) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LiveStreamSnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// that is transmitting the stream.
	ChannelId string `json:"channelId,omitempty"`

	// Description: The stream's description. The value cannot be longer
	// than 10000 characters.
	Description string `json:"description,omitempty"`

	IsDefaultStream bool `json:"isDefaultStream,omitempty"`

	// PublishedAt: The date and time that the stream was created. The value
	// is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Title: The stream's title. The value must be between 1 and 128
	// characters long.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStreamSnippet) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LiveStreamStatus: Brief description of the live stream status.
type LiveStreamStatus struct {
	// HealthStatus: The health status of the stream.
	HealthStatus *LiveStreamHealthStatus `json:"healthStatus,omitempty"`

	// Possible values:
	//   "active"
	//   "created"
	//   "error"
	//   "inactive"
	//   "ready"
	StreamStatus string `json:"streamStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "HealthStatus") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LiveStreamStatus) MarshalJSON() ([]byte, error) {
	type noMethod LiveStreamStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LocalizedProperty struct {
	Default string `json:"default,omitempty"`

	// DefaultLanguage: The language of the default property.
	DefaultLanguage *LanguageTag `json:"defaultLanguage,omitempty"`

	Localized []*LocalizedString `json:"localized,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Default") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LocalizedProperty) MarshalJSON() ([]byte, error) {
	type noMethod LocalizedProperty
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type LocalizedString struct {
	Language string `json:"language,omitempty"`

	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Language") to
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

// MonitorStreamInfo: Settings and Info of the monitor stream
type MonitorStreamInfo struct {
	// BroadcastStreamDelayMs: If you have set the enableMonitorStream
	// property to true, then this property determines the length of the
	// live broadcast delay.
	BroadcastStreamDelayMs int64 `json:"broadcastStreamDelayMs,omitempty"`

	// EmbedHtml: HTML code that embeds a player that plays the monitor
	// stream.
	EmbedHtml string `json:"embedHtml,omitempty"`

	// EnableMonitorStream: This value determines whether the monitor stream
	// is enabled for the broadcast. If the monitor stream is enabled, then
	// YouTube will broadcast the event content on a special stream intended
	// only for the broadcaster's consumption. The broadcaster can use the
	// stream to review the event content and also to identify the optimal
	// times to insert cuepoints.
	//
	// You need to set this value to true if you intend to have a broadcast
	// delay for your event.
	//
	// Note: This property cannot be updated once the broadcast is in the
	// testing or live state.
	EnableMonitorStream bool `json:"enableMonitorStream,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "BroadcastStreamDelayMs") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MonitorStreamInfo) MarshalJSON() ([]byte, error) {
	type noMethod MonitorStreamInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PageInfo: Paging details for lists of resources, including total
// number of items available and number of resources returned in a
// single page.
type PageInfo struct {
	// ResultsPerPage: The number of results included in the API response.
	ResultsPerPage int64 `json:"resultsPerPage,omitempty"`

	// TotalResults: The total number of results in the result set.
	TotalResults int64 `json:"totalResults,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ResultsPerPage") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PageInfo) MarshalJSON() ([]byte, error) {
	type noMethod PageInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Playlist: A playlist resource represents a YouTube playlist. A
// playlist is a collection of videos that can be viewed sequentially
// and shared with other users. A playlist can contain up to 200 videos,
// and YouTube does not limit the number of playlists that each user
// creates. By default, playlists are publicly visible to other users,
// but playlists can be public or private.
//
// YouTube also uses playlists to identify special collections of videos
// for a channel, such as:
// - uploaded videos
// - favorite videos
// - positively rated (liked) videos
// - watch history
// - watch later  To be more specific, these lists are associated with a
// channel, which is a collection of a person, group, or company's
// videos, playlists, and other YouTube information. You can retrieve
// the playlist IDs for each of these lists from the  channel resource
// for a given channel.
//
// You can then use the   playlistItems.list method to retrieve any of
// those lists. You can also add or remove items from those lists by
// calling the   playlistItems.insert and   playlistItems.delete
// methods.
type Playlist struct {
	// ContentDetails: The contentDetails object contains information like
	// video count.
	ContentDetails *PlaylistContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the playlist.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#playlist".
	Kind string `json:"kind,omitempty"`

	// Localizations: Localizations for different languages
	Localizations map[string]PlaylistLocalization `json:"localizations,omitempty"`

	// Player: The player object contains information that you would use to
	// play the playlist in an embedded player.
	Player *PlaylistPlayer `json:"player,omitempty"`

	// Snippet: The snippet object contains basic details about the
	// playlist, such as its title and description.
	Snippet *PlaylistSnippet `json:"snippet,omitempty"`

	// Status: The status object contains status information for the
	// playlist.
	Status *PlaylistStatus `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Playlist) MarshalJSON() ([]byte, error) {
	type noMethod Playlist
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistContentDetails struct {
	// ItemCount: The number of videos in the playlist.
	ItemCount int64 `json:"itemCount,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ItemCount") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaylistItem: A playlistItem resource identifies another resource,
// such as a video, that is included in a playlist. In addition, the
// playlistItem  resource contains details about the included resource
// that pertain specifically to how that resource is used in that
// playlist.
//
// YouTube uses playlists to identify special collections of videos for
// a channel, such as:
// - uploaded videos
// - favorite videos
// - positively rated (liked) videos
// - watch history
// - watch later  To be more specific, these lists are associated with a
// channel, which is a collection of a person, group, or company's
// videos, playlists, and other YouTube information.
//
// You can retrieve the playlist IDs for each of these lists from the
// channel resource  for a given channel. You can then use the
// playlistItems.list method to retrieve any of those lists. You can
// also add or remove items from those lists by calling the
// playlistItems.insert and   playlistItems.delete methods. For example,
// if a user gives a positive rating to a video, you would insert that
// video into the liked videos playlist for that user's channel.
type PlaylistItem struct {
	// ContentDetails: The contentDetails object is included in the resource
	// if the included item is a YouTube video. The object contains
	// additional information about the video.
	ContentDetails *PlaylistItemContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the playlist item.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#playlistItem".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the playlist
	// item, such as its title and position in the playlist.
	Snippet *PlaylistItemSnippet `json:"snippet,omitempty"`

	// Status: The status object contains information about the playlist
	// item's privacy status.
	Status *PlaylistItemStatus `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistItem) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistItemContentDetails struct {
	// EndAt: The time, measured in seconds from the start of the video,
	// when the video should stop playing. (The playlist owner can specify
	// the times when the video should start and stop playing when the video
	// is played in the context of the playlist.) By default, assume that
	// the video.endTime is the end of the video.
	EndAt string `json:"endAt,omitempty"`

	// Note: A user-generated note for this item.
	Note string `json:"note,omitempty"`

	// StartAt: The time, measured in seconds from the start of the video,
	// when the video should start playing. (The playlist owner can specify
	// the times when the video should start and stop playing when the video
	// is played in the context of the playlist.) The default value is 0.
	StartAt string `json:"startAt,omitempty"`

	// VideoId: The ID that YouTube uses to uniquely identify a video. To
	// retrieve the video resource, set the id query parameter to this value
	// in your API request.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EndAt") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistItemContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistItemContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistItemListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of playlist items that match the request criteria.
	Items []*PlaylistItem `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#playlistItemListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *PlaylistItemListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistItemListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaylistItemSnippet: Basic details about a playlist, including title,
// description and thumbnails.
type PlaylistItemSnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the user
	// that added the item to the playlist.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: Channel title for the channel that the playlist item
	// belongs to.
	ChannelTitle string `json:"channelTitle,omitempty"`

	// Description: The item's description.
	Description string `json:"description,omitempty"`

	// PlaylistId: The ID that YouTube uses to uniquely identify the
	// playlist that the playlist item is in.
	PlaylistId string `json:"playlistId,omitempty"`

	// Position: The order in which the item appears in the playlist. The
	// value uses a zero-based index, so the first item has a position of 0,
	// the second item has a position of 1, and so forth.
	Position int64 `json:"position,omitempty"`

	// PublishedAt: The date and time that the item was added to the
	// playlist. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// ResourceId: The id object contains information that can be used to
	// uniquely identify the resource that is included in the playlist as
	// the playlist item.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the playlist
	// item. For each object in the map, the key is the name of the
	// thumbnail image, and the value is an object that contains other
	// information about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The item's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistItemSnippet) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistItemSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaylistItemStatus: Information about the playlist item's privacy
// status.
type PlaylistItemStatus struct {
	// PrivacyStatus: This resource's privacy status.
	//
	// Possible values:
	//   "private"
	//   "public"
	//   "unlisted"
	PrivacyStatus string `json:"privacyStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "PrivacyStatus") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistItemStatus) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistItemStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of playlists that match the request criteria.
	Items []*Playlist `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#playlistListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *PlaylistListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaylistLocalization: Playlist localization setting
type PlaylistLocalization struct {
	// Description: The localized strings for playlist's description.
	Description string `json:"description,omitempty"`

	// Title: The localized strings for playlist's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistLocalization) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistLocalization
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistPlayer struct {
	// EmbedHtml: An <iframe> tag that embeds a player that will play the
	// playlist.
	EmbedHtml string `json:"embedHtml,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EmbedHtml") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistPlayer) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistPlayer
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaylistSnippet: Basic details about a playlist, including title,
// description and thumbnails.
type PlaylistSnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// that published the playlist.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: The channel title of the channel that the video belongs
	// to.
	ChannelTitle string `json:"channelTitle,omitempty"`

	// DefaultLanguage: The language of the playlist's default title and
	// description.
	DefaultLanguage string `json:"defaultLanguage,omitempty"`

	// Description: The playlist's description.
	Description string `json:"description,omitempty"`

	// Localized: Localized title and description, read-only.
	Localized *PlaylistLocalization `json:"localized,omitempty"`

	// PublishedAt: The date and time that the playlist was created. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Tags: Keyword tags associated with the playlist.
	Tags []string `json:"tags,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the playlist.
	// For each object in the map, the key is the name of the thumbnail
	// image, and the value is an object that contains other information
	// about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The playlist's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistSnippet) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlaylistStatus struct {
	// PrivacyStatus: The playlist's privacy status.
	//
	// Possible values:
	//   "private"
	//   "public"
	//   "unlisted"
	PrivacyStatus string `json:"privacyStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "PrivacyStatus") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaylistStatus) MarshalJSON() ([]byte, error) {
	type noMethod PlaylistStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PromotedItem: Describes a single promoted item.
type PromotedItem struct {
	// CustomMessage: A custom message to display for this promotion. This
	// field is currently ignored unless the promoted item is a website.
	CustomMessage string `json:"customMessage,omitempty"`

	// Id: Identifies the promoted item.
	Id *PromotedItemId `json:"id,omitempty"`

	// PromotedByContentOwner: If true, the content owner's name will be
	// used when displaying the promotion. This field can only be set when
	// the update is made on behalf of the content owner.
	PromotedByContentOwner bool `json:"promotedByContentOwner,omitempty"`

	// Timing: The temporal position within the video where the promoted
	// item will be displayed. If present, it overrides the default timing.
	Timing *InvideoTiming `json:"timing,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CustomMessage") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PromotedItem) MarshalJSON() ([]byte, error) {
	type noMethod PromotedItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PromotedItemId: Describes a single promoted item id. It is a union of
// various possible types.
type PromotedItemId struct {
	// RecentlyUploadedBy: If type is recentUpload, this field identifies
	// the channel from which to take the recent upload. If missing, the
	// channel is assumed to be the same channel for which the
	// invideoPromotion is set.
	RecentlyUploadedBy string `json:"recentlyUploadedBy,omitempty"`

	// Type: Describes the type of the promoted item.
	//
	// Possible values:
	//   "recentUpload"
	//   "video"
	//   "website"
	Type string `json:"type,omitempty"`

	// VideoId: If the promoted item represents a video, this field
	// represents the unique YouTube ID identifying it. This field will be
	// present only if type has the value video.
	VideoId string `json:"videoId,omitempty"`

	// WebsiteUrl: If the promoted item represents a website, this field
	// represents the url pointing to the website. This field will be
	// present only if type has the value website.
	WebsiteUrl string `json:"websiteUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "RecentlyUploadedBy")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PromotedItemId) MarshalJSON() ([]byte, error) {
	type noMethod PromotedItemId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PropertyValue: A pair Property / Value.
type PropertyValue struct {
	// Property: A property.
	Property string `json:"property,omitempty"`

	// Value: The property's value.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Property") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PropertyValue) MarshalJSON() ([]byte, error) {
	type noMethod PropertyValue
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ResourceId: A resource id is a generic reference that points to
// another YouTube resource.
type ResourceId struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the referred
	// resource, if that resource is a channel. This property is only
	// present if the resourceId.kind value is youtube#channel.
	ChannelId string `json:"channelId,omitempty"`

	// Kind: The type of the API resource.
	Kind string `json:"kind,omitempty"`

	// PlaylistId: The ID that YouTube uses to uniquely identify the
	// referred resource, if that resource is a playlist. This property is
	// only present if the resourceId.kind value is youtube#playlist.
	PlaylistId string `json:"playlistId,omitempty"`

	// VideoId: The ID that YouTube uses to uniquely identify the referred
	// resource, if that resource is a video. This property is only present
	// if the resourceId.kind value is youtube#video.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ResourceId) MarshalJSON() ([]byte, error) {
	type noMethod ResourceId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of results that match the search criteria.
	Items []*SearchResult `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#searchListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *SearchListResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchResult: A search result contains information about a YouTube
// video, channel, or playlist that matches the search parameters
// specified in an API request. While a search result points to a
// uniquely identifiable resource, like a video, it does not have its
// own persistent data.
type SearchResult struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The id object contains information that can be used to uniquely
	// identify the resource that matches the search request.
	Id *ResourceId `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#searchResult".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about a search
	// result, such as its title or description. For example, if the search
	// result is a video, then the title will be the video's title and the
	// description will be the video's description.
	Snippet *SearchResultSnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchResult) MarshalJSON() ([]byte, error) {
	type noMethod SearchResult
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchResultSnippet: Basic details about a search result, including
// title, description and thumbnails of the item referenced by the
// search result.
type SearchResultSnippet struct {
	// ChannelId: The value that YouTube uses to uniquely identify the
	// channel that published the resource that the search result
	// identifies.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: The title of the channel that published the resource
	// that the search result identifies.
	ChannelTitle string `json:"channelTitle,omitempty"`

	// Description: A description of the search result.
	Description string `json:"description,omitempty"`

	// LiveBroadcastContent: It indicates if the resource (video or channel)
	// has upcoming/active live broadcast content. Or it's "none" if there
	// is not any upcoming/active live broadcasts.
	//
	// Possible values:
	//   "live"
	//   "none"
	//   "upcoming"
	LiveBroadcastContent string `json:"liveBroadcastContent,omitempty"`

	// PublishedAt: The creation date and time of the resource that the
	// search result identifies. The value is specified in ISO 8601
	// (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the search
	// result. For each object in the map, the key is the name of the
	// thumbnail image, and the value is an object that contains other
	// information about the thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The title of the search result.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchResultSnippet) MarshalJSON() ([]byte, error) {
	type noMethod SearchResultSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Subscription: A subscription resource contains information about a
// YouTube user subscription. A subscription notifies a user when new
// videos are added to a channel or when another user takes one of
// several actions on YouTube, such as uploading a video, rating a
// video, or commenting on a video.
type Subscription struct {
	// ContentDetails: The contentDetails object contains basic statistics
	// about the subscription.
	ContentDetails *SubscriptionContentDetails `json:"contentDetails,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the subscription.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#subscription".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the
	// subscription, including its title and the channel that the user
	// subscribed to.
	Snippet *SubscriptionSnippet `json:"snippet,omitempty"`

	// SubscriberSnippet: The subscriberSnippet object contains basic
	// details about the sbuscriber.
	SubscriberSnippet *SubscriptionSubscriberSnippet `json:"subscriberSnippet,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ContentDetails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Subscription) MarshalJSON() ([]byte, error) {
	type noMethod Subscription
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SubscriptionContentDetails: Details about the content to witch a
// subscription refers.
type SubscriptionContentDetails struct {
	// ActivityType: The type of activity this subscription is for (only
	// uploads, everything).
	//
	// Possible values:
	//   "all"
	//   "uploads"
	ActivityType string `json:"activityType,omitempty"`

	// NewItemCount: The number of new items in the subscription since its
	// content was last read.
	NewItemCount int64 `json:"newItemCount,omitempty"`

	// TotalItemCount: The approximate number of items that the subscription
	// points to.
	TotalItemCount int64 `json:"totalItemCount,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ActivityType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SubscriptionContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod SubscriptionContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SubscriptionListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of subscriptions that match the request criteria.
	Items []*Subscription `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#subscriptionListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *SubscriptionListResponse) MarshalJSON() ([]byte, error) {
	type noMethod SubscriptionListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SubscriptionSnippet: Basic details about a subscription, including
// title, description and thumbnails of the subscribed item.
type SubscriptionSnippet struct {
	// ChannelId: The ID that YouTube uses to uniquely identify the
	// subscriber's channel.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: Channel title for the channel that the subscription
	// belongs to.
	ChannelTitle string `json:"channelTitle,omitempty"`

	// Description: The subscription's details.
	Description string `json:"description,omitempty"`

	// PublishedAt: The date and time that the subscription was created. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// ResourceId: The id object contains information about the channel that
	// the user subscribed to.
	ResourceId *ResourceId `json:"resourceId,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the video. For
	// each object in the map, the key is the name of the thumbnail image,
	// and the value is an object that contains other information about the
	// thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The subscription's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SubscriptionSnippet) MarshalJSON() ([]byte, error) {
	type noMethod SubscriptionSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SubscriptionSubscriberSnippet: Basic details about a subscription's
// subscriber including title, description, channel ID and thumbnails.
type SubscriptionSubscriberSnippet struct {
	// ChannelId: The channel ID of the subscriber.
	ChannelId string `json:"channelId,omitempty"`

	// Description: The description of the subscriber.
	Description string `json:"description,omitempty"`

	// Thumbnails: Thumbnails for this subscriber.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The title of the subscriber.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SubscriptionSubscriberSnippet) MarshalJSON() ([]byte, error) {
	type noMethod SubscriptionSubscriberSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Thumbnail: A thumbnail is an image representing a YouTube resource.
type Thumbnail struct {
	// Height: (Optional) Height of the thumbnail image.
	Height int64 `json:"height,omitempty"`

	// Url: The thumbnail image's URL.
	Url string `json:"url,omitempty"`

	// Width: (Optional) Width of the thumbnail image.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Thumbnail) MarshalJSON() ([]byte, error) {
	type noMethod Thumbnail
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ThumbnailDetails: Internal representation of thumbnails for a YouTube
// resource.
type ThumbnailDetails struct {
	// Default: The default image for this resource.
	Default *Thumbnail `json:"default,omitempty"`

	// High: The high quality image for this resource.
	High *Thumbnail `json:"high,omitempty"`

	// Maxres: The maximum resolution quality image for this resource.
	Maxres *Thumbnail `json:"maxres,omitempty"`

	// Medium: The medium quality image for this resource.
	Medium *Thumbnail `json:"medium,omitempty"`

	// Standard: The standard quality image for this resource.
	Standard *Thumbnail `json:"standard,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Default") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ThumbnailDetails) MarshalJSON() ([]byte, error) {
	type noMethod ThumbnailDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ThumbnailSetResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of thumbnails.
	Items []*ThumbnailDetails `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#thumbnailSetResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *ThumbnailSetResponse) MarshalJSON() ([]byte, error) {
	type noMethod ThumbnailSetResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TokenPagination: Stub token pagination template to suppress results.
type TokenPagination struct {
}

// Video: A video resource represents a YouTube video.
type Video struct {
	// AgeGating: Age restriction details related to a video. This data can
	// only be retrieved by the video owner.
	AgeGating *VideoAgeGating `json:"ageGating,omitempty"`

	// ContentDetails: The contentDetails object contains information about
	// the video content, including the length of the video and its aspect
	// ratio.
	ContentDetails *VideoContentDetails `json:"contentDetails,omitempty"`

	// ConversionPings: The conversionPings object encapsulates information
	// about url pings that need to be respected by the App in different
	// video contexts.
	ConversionPings *VideoConversionPings `json:"conversionPings,omitempty"`

	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// FileDetails: The fileDetails object encapsulates information about
	// the video file that was uploaded to YouTube, including the file's
	// resolution, duration, audio and video codecs, stream bitrates, and
	// more. This data can only be retrieved by the video owner.
	FileDetails *VideoFileDetails `json:"fileDetails,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the video.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#video".
	Kind string `json:"kind,omitempty"`

	// LiveStreamingDetails: The liveStreamingDetails object contains
	// metadata about a live video broadcast. The object will only be
	// present in a video resource if the video is an upcoming, live, or
	// completed live broadcast.
	LiveStreamingDetails *VideoLiveStreamingDetails `json:"liveStreamingDetails,omitempty"`

	// Localizations: List with all localizations.
	Localizations map[string]VideoLocalization `json:"localizations,omitempty"`

	// MonetizationDetails: The monetizationDetails object encapsulates
	// information about the monetization status of the video.
	MonetizationDetails *VideoMonetizationDetails `json:"monetizationDetails,omitempty"`

	// Player: The player object contains information that you would use to
	// play the video in an embedded player.
	Player *VideoPlayer `json:"player,omitempty"`

	// ProcessingDetails: The processingProgress object encapsulates
	// information about YouTube's progress in processing the uploaded video
	// file. The properties in the object identify the current processing
	// status and an estimate of the time remaining until YouTube finishes
	// processing the video. This part also indicates whether different
	// types of data or content, such as file details or thumbnail images,
	// are available for the video.
	//
	// The processingProgress object is designed to be polled so that the
	// video uploaded can track the progress that YouTube has made in
	// processing the uploaded video file. This data can only be retrieved
	// by the video owner.
	ProcessingDetails *VideoProcessingDetails `json:"processingDetails,omitempty"`

	// ProjectDetails: The projectDetails object contains information about
	// the project specific video metadata.
	ProjectDetails *VideoProjectDetails `json:"projectDetails,omitempty"`

	// RecordingDetails: The recordingDetails object encapsulates
	// information about the location, date and address where the video was
	// recorded.
	RecordingDetails *VideoRecordingDetails `json:"recordingDetails,omitempty"`

	// Snippet: The snippet object contains basic details about the video,
	// such as its title, description, and category.
	Snippet *VideoSnippet `json:"snippet,omitempty"`

	// Statistics: The statistics object contains statistics about the
	// video.
	Statistics *VideoStatistics `json:"statistics,omitempty"`

	// Status: The status object contains information about the video's
	// uploading, processing, and privacy statuses.
	Status *VideoStatus `json:"status,omitempty"`

	// Suggestions: The suggestions object encapsulates suggestions that
	// identify opportunities to improve the video quality or the metadata
	// for the uploaded video. This data can only be retrieved by the video
	// owner.
	Suggestions *VideoSuggestions `json:"suggestions,omitempty"`

	// TopicDetails: The topicDetails object encapsulates information about
	// Freebase topics associated with the video.
	TopicDetails *VideoTopicDetails `json:"topicDetails,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AgeGating") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Video) MarshalJSON() ([]byte, error) {
	type noMethod Video
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoAbuseReport struct {
	// Comments: Additional comments regarding the abuse report.
	Comments string `json:"comments,omitempty"`

	// Language: The language that the content was viewed in.
	Language string `json:"language,omitempty"`

	// ReasonId: The high-level, or primary, reason that the content is
	// abusive. The value is an abuse report reason ID.
	ReasonId string `json:"reasonId,omitempty"`

	// SecondaryReasonId: The specific, or secondary, reason that this
	// content is abusive (if available). The value is an abuse report
	// reason ID that is a valid secondary reason for the primary reason.
	SecondaryReasonId string `json:"secondaryReasonId,omitempty"`

	// VideoId: The ID that YouTube uses to uniquely identify the video.
	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Comments") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoAbuseReport) MarshalJSON() ([]byte, error) {
	type noMethod VideoAbuseReport
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoAbuseReportReason: A videoAbuseReportReason resource identifies
// a reason that a video could be reported as abusive. Video abuse
// report reasons are used with video.ReportAbuse.
type VideoAbuseReportReason struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of this abuse report reason.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoAbuseReportReason".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the abuse
	// report reason.
	Snippet *VideoAbuseReportReasonSnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoAbuseReportReason) MarshalJSON() ([]byte, error) {
	type noMethod VideoAbuseReportReason
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoAbuseReportReasonListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of valid abuse reasons that are used with
	// video.ReportAbuse.
	Items []*VideoAbuseReportReason `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoAbuseReportReasonListResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *VideoAbuseReportReasonListResponse) MarshalJSON() ([]byte, error) {
	type noMethod VideoAbuseReportReasonListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoAbuseReportReasonSnippet: Basic details about a video category,
// such as its localized title.
type VideoAbuseReportReasonSnippet struct {
	// Label: The localized label belonging to this abuse report reason.
	Label string `json:"label,omitempty"`

	// SecondaryReasons: The secondary reasons associated with this reason,
	// if any are available. (There might be 0 or more.)
	SecondaryReasons []*VideoAbuseReportSecondaryReason `json:"secondaryReasons,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Label") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoAbuseReportReasonSnippet) MarshalJSON() ([]byte, error) {
	type noMethod VideoAbuseReportReasonSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoAbuseReportSecondaryReason struct {
	// Id: The ID of this abuse report secondary reason.
	Id string `json:"id,omitempty"`

	// Label: The localized label for this abuse report secondary reason.
	Label string `json:"label,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoAbuseReportSecondaryReason) MarshalJSON() ([]byte, error) {
	type noMethod VideoAbuseReportSecondaryReason
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoAgeGating struct {
	// AlcoholContent: Indicates whether or not the video has alcoholic
	// beverage content. Only users of legal purchasing age in a particular
	// country, as identified by ICAP, can view the content.
	AlcoholContent bool `json:"alcoholContent,omitempty"`

	// Restricted: Age-restricted trailers. For redband trailers and
	// adult-rated video-games. Only users aged 18+ can view the content.
	// The the field is true the content is restricted to viewers aged 18+.
	// Otherwise The field won't be present.
	Restricted bool `json:"restricted,omitempty"`

	// VideoGameRating: Video game rating, if any.
	//
	// Possible values:
	//   "anyone"
	//   "m15Plus"
	//   "m16Plus"
	//   "m17Plus"
	VideoGameRating string `json:"videoGameRating,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AlcoholContent") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoAgeGating) MarshalJSON() ([]byte, error) {
	type noMethod VideoAgeGating
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoCategory: A videoCategory resource identifies a category that
// has been or could be associated with uploaded videos.
type VideoCategory struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// Id: The ID that YouTube uses to uniquely identify the video category.
	Id string `json:"id,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoCategory".
	Kind string `json:"kind,omitempty"`

	// Snippet: The snippet object contains basic details about the video
	// category, including its title.
	Snippet *VideoCategorySnippet `json:"snippet,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoCategory) MarshalJSON() ([]byte, error) {
	type noMethod VideoCategory
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoCategoryListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of video categories that can be associated with YouTube
	// videos. In this map, the video category ID is the map key, and its
	// value is the corresponding videoCategory resource.
	Items []*VideoCategory `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoCategoryListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *VideoCategoryListResponse) MarshalJSON() ([]byte, error) {
	type noMethod VideoCategoryListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoCategorySnippet: Basic details about a video category, such as
// its localized title.
type VideoCategorySnippet struct {
	Assignable bool `json:"assignable,omitempty"`

	// ChannelId: The YouTube channel that created the video category.
	ChannelId string `json:"channelId,omitempty"`

	// Title: The video category's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Assignable") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoCategorySnippet) MarshalJSON() ([]byte, error) {
	type noMethod VideoCategorySnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoContentDetails: Details about the content of a YouTube Video.
type VideoContentDetails struct {
	// Caption: The value of captions indicates whether the video has
	// captions or not.
	//
	// Possible values:
	//   "false"
	//   "true"
	Caption string `json:"caption,omitempty"`

	// ContentRating: Specifies the ratings that the video received under
	// various rating schemes.
	ContentRating *ContentRating `json:"contentRating,omitempty"`

	// CountryRestriction: The countryRestriction object contains
	// information about the countries where a video is (or is not)
	// viewable.
	CountryRestriction *AccessPolicy `json:"countryRestriction,omitempty"`

	// Definition: The value of definition indicates whether the video is
	// available in high definition or only in standard definition.
	//
	// Possible values:
	//   "hd"
	//   "sd"
	Definition string `json:"definition,omitempty"`

	// Dimension: The value of dimension indicates whether the video is
	// available in 3D or in 2D.
	Dimension string `json:"dimension,omitempty"`

	// Duration: The length of the video. The tag value is an ISO 8601
	// duration in the format PT#M#S, in which the letters PT indicate that
	// the value specifies a period of time, and the letters M and S refer
	// to length in minutes and seconds, respectively. The # characters
	// preceding the M and S letters are both integers that specify the
	// number of minutes (or seconds) of the video. For example, a value of
	// PT15M51S indicates that the video is 15 minutes and 51 seconds long.
	Duration string `json:"duration,omitempty"`

	// LicensedContent: The value of is_license_content indicates whether
	// the video is licensed content.
	LicensedContent bool `json:"licensedContent,omitempty"`

	// RegionRestriction: The regionRestriction object contains information
	// about the countries where a video is (or is not) viewable. The object
	// will contain either the contentDetails.regionRestriction.allowed
	// property or the contentDetails.regionRestriction.blocked property.
	RegionRestriction *VideoContentDetailsRegionRestriction `json:"regionRestriction,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Caption") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoContentDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoContentDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoContentDetailsRegionRestriction: DEPRECATED Region restriction
// of the video.
type VideoContentDetailsRegionRestriction struct {
	// Allowed: A list of region codes that identify countries where the
	// video is viewable. If this property is present and a country is not
	// listed in its value, then the video is blocked from appearing in that
	// country. If this property is present and contains an empty list, the
	// video is blocked in all countries.
	Allowed []string `json:"allowed,omitempty"`

	// Blocked: A list of region codes that identify countries where the
	// video is blocked. If this property is present and a country is not
	// listed in its value, then the video is viewable in that country. If
	// this property is present and contains an empty list, the video is
	// viewable in all countries.
	Blocked []string `json:"blocked,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Allowed") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoContentDetailsRegionRestriction) MarshalJSON() ([]byte, error) {
	type noMethod VideoContentDetailsRegionRestriction
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoConversionPing struct {
	// Context: Defines the context of the ping.
	//
	// Possible values:
	//   "comment"
	//   "dislike"
	//   "like"
	//   "share"
	Context string `json:"context,omitempty"`

	// ConversionUrl: The url (without the schema) that the app shall send
	// the ping to. It's at caller's descretion to decide which schema to
	// use (http vs https) Example of a returned url:
	// //googleads.g.doubleclick.net/pagead/
	// viewthroughconversion/962985656/?data=path%3DtHe_path%3Btype%3D
	// like%3Butuid%3DGISQtTNGYqaYl4sKxoVvKA%3Bytvid%3DUrIaJUvIQDg&labe=defau
	// lt The caller must append biscotti authentication (ms param in case
	// of mobile, for example) to this ping.
	ConversionUrl string `json:"conversionUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Context") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoConversionPing) MarshalJSON() ([]byte, error) {
	type noMethod VideoConversionPing
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoConversionPings struct {
	// Pings: Pings that the app shall fire for a video (authenticated by
	// biscotti cookie). Each ping has a context, in which the app must fire
	// the ping, and a url identifying the ping.
	Pings []*VideoConversionPing `json:"pings,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Pings") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoConversionPings) MarshalJSON() ([]byte, error) {
	type noMethod VideoConversionPings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoFileDetails: Describes original video file properties, including
// technical details about audio and video streams, but also metadata
// information like content length, digitization time, or geotagging
// information.
type VideoFileDetails struct {
	// AudioStreams: A list of audio streams contained in the uploaded video
	// file. Each item in the list contains detailed metadata about an audio
	// stream.
	AudioStreams []*VideoFileDetailsAudioStream `json:"audioStreams,omitempty"`

	// BitrateBps: The uploaded video file's combined (video and audio)
	// bitrate in bits per second.
	BitrateBps uint64 `json:"bitrateBps,omitempty,string"`

	// Container: The uploaded video file's container format.
	Container string `json:"container,omitempty"`

	// CreationTime: The date and time when the uploaded video file was
	// created. The value is specified in ISO 8601 format. Currently, the
	// following ISO 8601 formats are supported:
	// - Date only: YYYY-MM-DD
	// - Naive time: YYYY-MM-DDTHH:MM:SS
	// - Time with timezone: YYYY-MM-DDTHH:MM:SS+HH:MM
	CreationTime string `json:"creationTime,omitempty"`

	// DurationMs: The length of the uploaded video in milliseconds.
	DurationMs uint64 `json:"durationMs,omitempty,string"`

	// FileName: The uploaded file's name. This field is present whether a
	// video file or another type of file was uploaded.
	FileName string `json:"fileName,omitempty"`

	// FileSize: The uploaded file's size in bytes. This field is present
	// whether a video file or another type of file was uploaded.
	FileSize uint64 `json:"fileSize,omitempty,string"`

	// FileType: The uploaded file's type as detected by YouTube's video
	// processing engine. Currently, YouTube only processes video files, but
	// this field is present whether a video file or another type of file
	// was uploaded.
	//
	// Possible values:
	//   "archive"
	//   "audio"
	//   "document"
	//   "image"
	//   "other"
	//   "project"
	//   "video"
	FileType string `json:"fileType,omitempty"`

	// RecordingLocation: Geographic coordinates that identify the place
	// where the uploaded video was recorded. Coordinates are defined using
	// WGS 84.
	RecordingLocation *GeoPoint `json:"recordingLocation,omitempty"`

	// VideoStreams: A list of video streams contained in the uploaded video
	// file. Each item in the list contains detailed metadata about a video
	// stream.
	VideoStreams []*VideoFileDetailsVideoStream `json:"videoStreams,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AudioStreams") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoFileDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoFileDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoFileDetailsAudioStream: Information about an audio stream.
type VideoFileDetailsAudioStream struct {
	// BitrateBps: The audio stream's bitrate, in bits per second.
	BitrateBps uint64 `json:"bitrateBps,omitempty,string"`

	// ChannelCount: The number of audio channels that the stream contains.
	ChannelCount int64 `json:"channelCount,omitempty"`

	// Codec: The audio codec that the stream uses.
	Codec string `json:"codec,omitempty"`

	// Vendor: A value that uniquely identifies a video vendor. Typically,
	// the value is a four-letter vendor code.
	Vendor string `json:"vendor,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BitrateBps") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoFileDetailsAudioStream) MarshalJSON() ([]byte, error) {
	type noMethod VideoFileDetailsAudioStream
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoFileDetailsVideoStream: Information about a video stream.
type VideoFileDetailsVideoStream struct {
	// AspectRatio: The video content's display aspect ratio, which
	// specifies the aspect ratio in which the video should be displayed.
	AspectRatio float64 `json:"aspectRatio,omitempty"`

	// BitrateBps: The video stream's bitrate, in bits per second.
	BitrateBps uint64 `json:"bitrateBps,omitempty,string"`

	// Codec: The video codec that the stream uses.
	Codec string `json:"codec,omitempty"`

	// FrameRateFps: The video stream's frame rate, in frames per second.
	FrameRateFps float64 `json:"frameRateFps,omitempty"`

	// HeightPixels: The encoded video content's height in pixels.
	HeightPixels int64 `json:"heightPixels,omitempty"`

	// Rotation: The amount that YouTube needs to rotate the original source
	// content to properly display the video.
	//
	// Possible values:
	//   "clockwise"
	//   "counterClockwise"
	//   "none"
	//   "other"
	//   "upsideDown"
	Rotation string `json:"rotation,omitempty"`

	// Vendor: A value that uniquely identifies a video vendor. Typically,
	// the value is a four-letter vendor code.
	Vendor string `json:"vendor,omitempty"`

	// WidthPixels: The encoded video content's width in pixels. You can
	// calculate the video's encoding aspect ratio as
	// width_pixels / height_pixels.
	WidthPixels int64 `json:"widthPixels,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AspectRatio") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoFileDetailsVideoStream) MarshalJSON() ([]byte, error) {
	type noMethod VideoFileDetailsVideoStream
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoGetRatingResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of ratings that match the request criteria.
	Items []*VideoRating `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoGetRatingResponse".
	Kind string `json:"kind,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *VideoGetRatingResponse) MarshalJSON() ([]byte, error) {
	type noMethod VideoGetRatingResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoListResponse struct {
	// Etag: Etag of this resource.
	Etag string `json:"etag,omitempty"`

	// EventId: Serialized EventId of the request which produced this
	// response.
	EventId string `json:"eventId,omitempty"`

	// Items: A list of videos that match the request criteria.
	Items []*Video `json:"items,omitempty"`

	// Kind: Identifies what kind of resource this is. Value: the fixed
	// string "youtube#videoListResponse".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the next page in the result set.
	NextPageToken string `json:"nextPageToken,omitempty"`

	PageInfo *PageInfo `json:"pageInfo,omitempty"`

	// PrevPageToken: The token that can be used as the value of the
	// pageToken parameter to retrieve the previous page in the result set.
	PrevPageToken string `json:"prevPageToken,omitempty"`

	TokenPagination *TokenPagination `json:"tokenPagination,omitempty"`

	// VisitorId: The visitorId identifies the visitor.
	VisitorId string `json:"visitorId,omitempty"`

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

func (s *VideoListResponse) MarshalJSON() ([]byte, error) {
	type noMethod VideoListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoLiveStreamingDetails: Details about the live streaming metadata.
type VideoLiveStreamingDetails struct {
	// ActualEndTime: The time that the broadcast actually ended. The value
	// is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format. This value
	// will not be available until the broadcast is over.
	ActualEndTime string `json:"actualEndTime,omitempty"`

	// ActualStartTime: The time that the broadcast actually started. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format. This
	// value will not be available until the broadcast begins.
	ActualStartTime string `json:"actualStartTime,omitempty"`

	// ConcurrentViewers: The number of viewers currently watching the
	// broadcast. The property and its value will be present if the
	// broadcast has current viewers and the broadcast owner has not hidden
	// the viewcount for the video. Note that YouTube stops tracking the
	// number of concurrent viewers for a broadcast when the broadcast ends.
	// So, this property would not identify the number of viewers watching
	// an archived video of a live broadcast that already ended.
	ConcurrentViewers uint64 `json:"concurrentViewers,omitempty,string"`

	// ScheduledEndTime: The time that the broadcast is scheduled to end.
	// The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	// If the value is empty or the property is not present, then the
	// broadcast is scheduled to continue indefinitely.
	ScheduledEndTime string `json:"scheduledEndTime,omitempty"`

	// ScheduledStartTime: The time that the broadcast is scheduled to
	// begin. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ)
	// format.
	ScheduledStartTime string `json:"scheduledStartTime,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ActualEndTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoLiveStreamingDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoLiveStreamingDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoLocalization: Localized versions of certain video properties
// (e.g. title).
type VideoLocalization struct {
	// Description: Localized version of the video's description.
	Description string `json:"description,omitempty"`

	// Title: Localized version of the video's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoLocalization) MarshalJSON() ([]byte, error) {
	type noMethod VideoLocalization
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoMonetizationDetails: Details about monetization of a YouTube
// Video.
type VideoMonetizationDetails struct {
	// Access: The value of access indicates whether the video can be
	// monetized or not.
	Access *AccessPolicy `json:"access,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Access") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoMonetizationDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoMonetizationDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoPlayer: Player to be used for a video playback.
type VideoPlayer struct {
	// EmbedHtml: An <iframe> tag that embeds a player that will play the
	// video.
	EmbedHtml string `json:"embedHtml,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EmbedHtml") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoPlayer) MarshalJSON() ([]byte, error) {
	type noMethod VideoPlayer
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoProcessingDetails: Describes processing status and progress and
// availability of some other Video resource parts.
type VideoProcessingDetails struct {
	// EditorSuggestionsAvailability: This value indicates whether video
	// editing suggestions, which might improve video quality or the
	// playback experience, are available for the video. You can retrieve
	// these suggestions by requesting the suggestions part in your
	// videos.list() request.
	EditorSuggestionsAvailability string `json:"editorSuggestionsAvailability,omitempty"`

	// FileDetailsAvailability: This value indicates whether file details
	// are available for the uploaded video. You can retrieve a video's file
	// details by requesting the fileDetails part in your videos.list()
	// request.
	FileDetailsAvailability string `json:"fileDetailsAvailability,omitempty"`

	// ProcessingFailureReason: The reason that YouTube failed to process
	// the video. This property will only have a value if the
	// processingStatus property's value is failed.
	//
	// Possible values:
	//   "other"
	//   "streamingFailed"
	//   "transcodeFailed"
	//   "uploadFailed"
	ProcessingFailureReason string `json:"processingFailureReason,omitempty"`

	// ProcessingIssuesAvailability: This value indicates whether the video
	// processing engine has generated suggestions that might improve
	// YouTube's ability to process the the video, warnings that explain
	// video processing problems, or errors that cause video processing
	// problems. You can retrieve these suggestions by requesting the
	// suggestions part in your videos.list() request.
	ProcessingIssuesAvailability string `json:"processingIssuesAvailability,omitempty"`

	// ProcessingProgress: The processingProgress object contains
	// information about the progress YouTube has made in processing the
	// video. The values are really only relevant if the video's processing
	// status is processing.
	ProcessingProgress *VideoProcessingDetailsProcessingProgress `json:"processingProgress,omitempty"`

	// ProcessingStatus: The video's processing status. This value indicates
	// whether YouTube was able to process the video or if the video is
	// still being processed.
	//
	// Possible values:
	//   "failed"
	//   "processing"
	//   "succeeded"
	//   "terminated"
	ProcessingStatus string `json:"processingStatus,omitempty"`

	// TagSuggestionsAvailability: This value indicates whether keyword
	// (tag) suggestions are available for the video. Tags can be added to a
	// video's metadata to make it easier for other users to find the video.
	// You can retrieve these suggestions by requesting the suggestions part
	// in your videos.list() request.
	TagSuggestionsAvailability string `json:"tagSuggestionsAvailability,omitempty"`

	// ThumbnailsAvailability: This value indicates whether thumbnail images
	// have been generated for the video.
	ThumbnailsAvailability string `json:"thumbnailsAvailability,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "EditorSuggestionsAvailability") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoProcessingDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoProcessingDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoProcessingDetailsProcessingProgress: Video processing progress
// and completion time estimate.
type VideoProcessingDetailsProcessingProgress struct {
	// PartsProcessed: The number of parts of the video that YouTube has
	// already processed. You can estimate the percentage of the video that
	// YouTube has already processed by calculating:
	// 100 * parts_processed / parts_total
	//
	// Note that since the estimated number of parts could increase without
	// a corresponding increase in the number of parts that have already
	// been processed, it is possible that the calculated progress could
	// periodically decrease while YouTube processes a video.
	PartsProcessed uint64 `json:"partsProcessed,omitempty,string"`

	// PartsTotal: An estimate of the total number of parts that need to be
	// processed for the video. The number may be updated with more precise
	// estimates while YouTube processes the video.
	PartsTotal uint64 `json:"partsTotal,omitempty,string"`

	// TimeLeftMs: An estimate of the amount of time, in millseconds, that
	// YouTube needs to finish processing the video.
	TimeLeftMs uint64 `json:"timeLeftMs,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "PartsProcessed") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoProcessingDetailsProcessingProgress) MarshalJSON() ([]byte, error) {
	type noMethod VideoProcessingDetailsProcessingProgress
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoProjectDetails: Project specific details about the content of a
// YouTube Video.
type VideoProjectDetails struct {
	// Tags: A list of project tags associated with the video during the
	// upload.
	Tags []string `json:"tags,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Tags") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoProjectDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoProjectDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VideoRating struct {
	// Possible values:
	//   "dislike"
	//   "like"
	//   "none"
	//   "unspecified"
	Rating string `json:"rating,omitempty"`

	VideoId string `json:"videoId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Rating") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoRating) MarshalJSON() ([]byte, error) {
	type noMethod VideoRating
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoRecordingDetails: Recording information associated with the
// video.
type VideoRecordingDetails struct {
	// Location: The geolocation information associated with the video.
	Location *GeoPoint `json:"location,omitempty"`

	// LocationDescription: The text description of the location where the
	// video was recorded.
	LocationDescription string `json:"locationDescription,omitempty"`

	// RecordingDate: The date and time when the video was recorded. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sssZ) format.
	RecordingDate string `json:"recordingDate,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Location") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoRecordingDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoRecordingDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoSnippet: Basic details about a video, including title,
// description, uploader, thumbnails and category.
type VideoSnippet struct {
	// CategoryId: The YouTube video category associated with the video.
	CategoryId string `json:"categoryId,omitempty"`

	// ChannelId: The ID that YouTube uses to uniquely identify the channel
	// that the video was uploaded to.
	ChannelId string `json:"channelId,omitempty"`

	// ChannelTitle: Channel title for the channel that the video belongs
	// to.
	ChannelTitle string `json:"channelTitle,omitempty"`

	// DefaultAudioLanguage: The default_audio_language property specifies
	// the language spoken in the video's default audio track.
	DefaultAudioLanguage string `json:"defaultAudioLanguage,omitempty"`

	// DefaultLanguage: The language of the videos's default snippet.
	DefaultLanguage string `json:"defaultLanguage,omitempty"`

	// Description: The video's description.
	Description string `json:"description,omitempty"`

	// LiveBroadcastContent: Indicates if the video is an upcoming/active
	// live broadcast. Or it's "none" if the video is not an upcoming/active
	// live broadcast.
	//
	// Possible values:
	//   "live"
	//   "none"
	//   "upcoming"
	LiveBroadcastContent string `json:"liveBroadcastContent,omitempty"`

	// Localized: Localized snippet selected with the hl parameter. If no
	// such localization exists, this field is populated with the default
	// snippet. (Read-only)
	Localized *VideoLocalization `json:"localized,omitempty"`

	// PublishedAt: The date and time that the video was uploaded. The value
	// is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishedAt string `json:"publishedAt,omitempty"`

	// Tags: A list of keyword tags associated with the video. Tags may
	// contain spaces.
	Tags []string `json:"tags,omitempty"`

	// Thumbnails: A map of thumbnail images associated with the video. For
	// each object in the map, the key is the name of the thumbnail image,
	// and the value is an object that contains other information about the
	// thumbnail.
	Thumbnails *ThumbnailDetails `json:"thumbnails,omitempty"`

	// Title: The video's title.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CategoryId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoSnippet) MarshalJSON() ([]byte, error) {
	type noMethod VideoSnippet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoStatistics: Statistics about the video, such as the number of
// times the video was viewed or liked.
type VideoStatistics struct {
	// CommentCount: The number of comments for the video.
	CommentCount uint64 `json:"commentCount,omitempty,string"`

	// DislikeCount: The number of users who have indicated that they
	// disliked the video by giving it a negative rating.
	DislikeCount uint64 `json:"dislikeCount,omitempty,string"`

	// FavoriteCount: The number of users who currently have the video
	// marked as a favorite video.
	FavoriteCount uint64 `json:"favoriteCount,omitempty,string"`

	// LikeCount: The number of users who have indicated that they liked the
	// video by giving it a positive rating.
	LikeCount uint64 `json:"likeCount,omitempty,string"`

	// ViewCount: The number of times the video has been viewed.
	ViewCount uint64 `json:"viewCount,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "CommentCount") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoStatistics) MarshalJSON() ([]byte, error) {
	type noMethod VideoStatistics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoStatus: Basic details about a video category, such as its
// localized title.
type VideoStatus struct {
	// Embeddable: This value indicates if the video can be embedded on
	// another website.
	Embeddable bool `json:"embeddable,omitempty"`

	// FailureReason: This value explains why a video failed to upload. This
	// property is only present if the uploadStatus property indicates that
	// the upload failed.
	//
	// Possible values:
	//   "codec"
	//   "conversion"
	//   "emptyFile"
	//   "invalidFile"
	//   "tooSmall"
	//   "uploadAborted"
	FailureReason string `json:"failureReason,omitempty"`

	// License: The video's license.
	//
	// Possible values:
	//   "creativeCommon"
	//   "youtube"
	License string `json:"license,omitempty"`

	// PrivacyStatus: The video's privacy status.
	//
	// Possible values:
	//   "private"
	//   "public"
	//   "unlisted"
	PrivacyStatus string `json:"privacyStatus,omitempty"`

	// PublicStatsViewable: This value indicates if the extended video
	// statistics on the watch page can be viewed by everyone. Note that the
	// view count, likes, etc will still be visible if this is disabled.
	PublicStatsViewable bool `json:"publicStatsViewable,omitempty"`

	// PublishAt: The date and time when the video is scheduled to publish.
	// It can be set only if the privacy status of the video is private. The
	// value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.
	PublishAt string `json:"publishAt,omitempty"`

	// RejectionReason: This value explains why YouTube rejected an uploaded
	// video. This property is only present if the uploadStatus property
	// indicates that the upload was rejected.
	//
	// Possible values:
	//   "claim"
	//   "copyright"
	//   "duplicate"
	//   "inappropriate"
	//   "length"
	//   "termsOfUse"
	//   "trademark"
	//   "uploaderAccountClosed"
	//   "uploaderAccountSuspended"
	RejectionReason string `json:"rejectionReason,omitempty"`

	// UploadStatus: The status of the uploaded video.
	//
	// Possible values:
	//   "deleted"
	//   "failed"
	//   "processed"
	//   "rejected"
	//   "uploaded"
	UploadStatus string `json:"uploadStatus,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Embeddable") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoStatus) MarshalJSON() ([]byte, error) {
	type noMethod VideoStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoSuggestions: Specifies suggestions on how to improve video
// content, including encoding hints, tag suggestions, and editor
// suggestions.
type VideoSuggestions struct {
	// EditorSuggestions: A list of video editing operations that might
	// improve the video quality or playback experience of the uploaded
	// video.
	//
	// Possible values:
	//   "audioQuietAudioSwap"
	//   "videoAutoLevels"
	//   "videoCrop"
	//   "videoStabilize"
	EditorSuggestions []string `json:"editorSuggestions,omitempty"`

	// ProcessingErrors: A list of errors that will prevent YouTube from
	// successfully processing the uploaded video video. These errors
	// indicate that, regardless of the video's current processing status,
	// eventually, that status will almost certainly be failed.
	//
	// Possible values:
	//   "archiveFile"
	//   "audioFile"
	//   "docFile"
	//   "imageFile"
	//   "notAVideoFile"
	//   "projectFile"
	ProcessingErrors []string `json:"processingErrors,omitempty"`

	// ProcessingHints: A list of suggestions that may improve YouTube's
	// ability to process the video.
	//
	// Possible values:
	//   "nonStreamableMov"
	//   "sendBestQualityVideo"
	ProcessingHints []string `json:"processingHints,omitempty"`

	// ProcessingWarnings: A list of reasons why YouTube may have difficulty
	// transcoding the uploaded video or that might result in an erroneous
	// transcoding. These warnings are generated before YouTube actually
	// processes the uploaded video file. In addition, they identify issues
	// that are unlikely to cause the video processing to fail but that
	// might cause problems such as sync issues, video artifacts, or a
	// missing audio track.
	//
	// Possible values:
	//   "hasEditlist"
	//   "inconsistentResolution"
	//   "problematicAudioCodec"
	//   "problematicVideoCodec"
	//   "unknownAudioCodec"
	//   "unknownContainer"
	//   "unknownVideoCodec"
	ProcessingWarnings []string `json:"processingWarnings,omitempty"`

	// TagSuggestions: A list of keyword tags that could be added to the
	// video's metadata to increase the likelihood that users will locate
	// your video when searching or browsing on YouTube.
	TagSuggestions []*VideoSuggestionsTagSuggestion `json:"tagSuggestions,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EditorSuggestions")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoSuggestions) MarshalJSON() ([]byte, error) {
	type noMethod VideoSuggestions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoSuggestionsTagSuggestion: A single tag suggestion with it's
// relevance information.
type VideoSuggestionsTagSuggestion struct {
	// CategoryRestricts: A set of video categories for which the tag is
	// relevant. You can use this information to display appropriate tag
	// suggestions based on the video category that the video uploader
	// associates with the video. By default, tag suggestions are relevant
	// for all categories if there are no restricts defined for the keyword.
	CategoryRestricts []string `json:"categoryRestricts,omitempty"`

	// Tag: The keyword tag suggested for the video.
	Tag string `json:"tag,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CategoryRestricts")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoSuggestionsTagSuggestion) MarshalJSON() ([]byte, error) {
	type noMethod VideoSuggestionsTagSuggestion
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VideoTopicDetails: Freebase topic information related to the video.
type VideoTopicDetails struct {
	// RelevantTopicIds: Similar to topic_id, except that these topics are
	// merely relevant to the video. These are topics that may be mentioned
	// in, or appear in the video. You can retrieve information about each
	// topic using Freebase Topic API.
	RelevantTopicIds []string `json:"relevantTopicIds,omitempty"`

	// TopicIds: A list of Freebase topic IDs that are centrally associated
	// with the video. These are topics that are centrally featured in the
	// video, and it can be said that the video is mainly about each of
	// these. You can retrieve information about each topic using the
	// Freebase Topic API.
	TopicIds []string `json:"topicIds,omitempty"`

	// ForceSendFields is a list of field names (e.g. "RelevantTopicIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VideoTopicDetails) MarshalJSON() ([]byte, error) {
	type noMethod VideoTopicDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WatchSettings: Branding properties for the watch.
type WatchSettings struct {
	// BackgroundColor: The text color for the video watch page's branded
	// area.
	BackgroundColor string `json:"backgroundColor,omitempty"`

	// FeaturedPlaylistId: An ID that uniquely identifies a playlist that
	// displays next to the video player.
	FeaturedPlaylistId string `json:"featuredPlaylistId,omitempty"`

	// TextColor: The background color for the video watch page's branded
	// area.
	TextColor string `json:"textColor,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BackgroundColor") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WatchSettings) MarshalJSON() ([]byte, error) {
	type noMethod WatchSettings
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "youtube.activities.insert":

type ActivitiesInsertCall struct {
	s        *Service
	part     string
	activity *Activity
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Insert: Posts a bulletin for a specific channel. (The user submitting
// the request must be authorized to act on the channel's
// behalf.)
//
// Note: Even though an activity resource can contain information about
// actions like a user rating a video or marking a video as a favorite,
// you need to use other API methods to generate those activity
// resources. For example, you would use the API's videos.rate() method
// to rate a video and the playlistItems.insert() method to mark a video
// as a favorite.
func (r *ActivitiesService) Insert(part string, activity *Activity) *ActivitiesInsertCall {
	c := &ActivitiesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.activity = activity
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
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities")
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

// Do executes the "youtube.activities.insert" call.
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
	//   "description": "Posts a bulletin for a specific channel. (The user submitting the request must be authorized to act on the channel's behalf.)\n\nNote: Even though an activity resource can contain information about actions like a user rating a video or marking a video as a favorite, you need to use other API methods to generate those activity resources. For example, you would use the API's videos.rate() method to rate a video and the playlistItems.insert() method to mark a video as a favorite.",
	//   "httpMethod": "POST",
	//   "id": "youtube.activities.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities",
	//   "request": {
	//     "$ref": "Activity"
	//   },
	//   "response": {
	//     "$ref": "Activity"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.activities.list":

type ActivitiesListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of channel activity events that match the
// request criteria. For example, you can retrieve events associated
// with a particular channel, events associated with the user's
// subscriptions and Google+ friends, or the YouTube home page feed,
// which is customized for each user.
func (r *ActivitiesService) List(part string) *ActivitiesListCall {
	c := &ActivitiesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// ChannelId sets the optional parameter "channelId": The channelId
// parameter specifies a unique YouTube channel ID. The API will then
// return a list of that channel's activities.
func (c *ActivitiesListCall) ChannelId(channelId string) *ActivitiesListCall {
	c.opt_["channelId"] = channelId
	return c
}

// Home sets the optional parameter "home": Set this parameter's value
// to true to retrieve the activity feed that displays on the YouTube
// home page for the currently authenticated user.
func (c *ActivitiesListCall) Home(home bool) *ActivitiesListCall {
	c.opt_["home"] = home
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *ActivitiesListCall) MaxResults(maxResults int64) *ActivitiesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": Set this parameter's value
// to true to retrieve a feed of the authenticated user's activities.
func (c *ActivitiesListCall) Mine(mine bool) *ActivitiesListCall {
	c.opt_["mine"] = mine
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *ActivitiesListCall) PageToken(pageToken string) *ActivitiesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PublishedAfter sets the optional parameter "publishedAfter": The
// publishedAfter parameter specifies the earliest date and time that an
// activity could have occurred for that activity to be included in the
// API response. If the parameter value specifies a day, but not a time,
// then any activities that occurred that day will be included in the
// result set. The value is specified in ISO 8601
// (YYYY-MM-DDThh:mm:ss.sZ) format.
func (c *ActivitiesListCall) PublishedAfter(publishedAfter string) *ActivitiesListCall {
	c.opt_["publishedAfter"] = publishedAfter
	return c
}

// PublishedBefore sets the optional parameter "publishedBefore": The
// publishedBefore parameter specifies the date and time before which an
// activity must have occurred for that activity to be included in the
// API response. If the parameter value specifies a day, but not a time,
// then any activities that occurred that day will be excluded from the
// result set. The value is specified in ISO 8601
// (YYYY-MM-DDThh:mm:ss.sZ) format.
func (c *ActivitiesListCall) PublishedBefore(publishedBefore string) *ActivitiesListCall {
	c.opt_["publishedBefore"] = publishedBefore
	return c
}

// RegionCode sets the optional parameter "regionCode": The regionCode
// parameter instructs the API to return results for the specified
// country. The parameter value is an ISO 3166-1 alpha-2 country code.
// YouTube uses this value when the authorized user's previous activity
// on YouTube does not provide enough information to generate the
// activity feed.
func (c *ActivitiesListCall) RegionCode(regionCode string) *ActivitiesListCall {
	c.opt_["regionCode"] = regionCode
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
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["home"]; ok {
		params.Set("home", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["publishedAfter"]; ok {
		params.Set("publishedAfter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["publishedBefore"]; ok {
		params.Set("publishedBefore", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["regionCode"]; ok {
		params.Set("regionCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities")
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

// Do executes the "youtube.activities.list" call.
// Exactly one of *ActivityListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ActivityListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ActivitiesListCall) Do() (*ActivityListResponse, error) {
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
	ret := &ActivityListResponse{
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
	//   "description": "Returns a list of channel activity events that match the request criteria. For example, you can retrieve events associated with a particular channel, events associated with the user's subscriptions and Google+ friends, or the YouTube home page feed, which is customized for each user.",
	//   "httpMethod": "GET",
	//   "id": "youtube.activities.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter specifies a unique YouTube channel ID. The API will then return a list of that channel's activities.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "home": {
	//       "description": "Set this parameter's value to true to retrieve the activity feed that displays on the YouTube home page for the currently authenticated user.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "Set this parameter's value to true to retrieve a feed of the authenticated user's activities.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more activity resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in an activity resource, the snippet property contains other properties that identify the type of activity, a display title for the activity, and so forth. If you set part=snippet, the API response will also contain all of those nested properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "publishedAfter": {
	//       "description": "The publishedAfter parameter specifies the earliest date and time that an activity could have occurred for that activity to be included in the API response. If the parameter value specifies a day, but not a time, then any activities that occurred that day will be included in the result set. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.",
	//       "format": "date-time",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "publishedBefore": {
	//       "description": "The publishedBefore parameter specifies the date and time before which an activity must have occurred for that activity to be included in the API response. If the parameter value specifies a day, but not a time, then any activities that occurred that day will be excluded from the result set. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sZ) format.",
	//       "format": "date-time",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "regionCode": {
	//       "description": "The regionCode parameter instructs the API to return results for the specified country. The parameter value is an ISO 3166-1 alpha-2 country code. YouTube uses this value when the authorized user's previous activity on YouTube does not provide enough information to generate the activity feed.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities",
	//   "response": {
	//     "$ref": "ActivityListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly"
	//   ]
	// }

}

// method id "youtube.captions.delete":

type CaptionsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a specified caption track.
func (r *CaptionsService) Delete(id string) *CaptionsDeleteCall {
	c := &CaptionsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOf sets the optional parameter "onBehalfOf": ID of the
// Google+ Page for the channel that the request is be on behalf of
func (c *CaptionsDeleteCall) OnBehalfOf(onBehalfOf string) *CaptionsDeleteCall {
	c.opt_["onBehalfOf"] = onBehalfOf
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *CaptionsDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *CaptionsDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CaptionsDeleteCall) Fields(s ...googleapi.Field) *CaptionsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CaptionsDeleteCall) Context(ctx context.Context) *CaptionsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *CaptionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOf"]; ok {
		params.Set("onBehalfOf", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "captions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.captions.delete" call.
func (c *CaptionsDeleteCall) Do() error {
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
	//   "description": "Deletes a specified caption track.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.captions.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter identifies the caption track that is being deleted. The value is a caption track ID as identified by the id property in a caption resource.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOf": {
	//       "description": "ID of the Google+ Page for the channel that the request is be on behalf of",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "captions",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.captions.download":

type CaptionsDownloadCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Download: Downloads a caption track. The caption track is returned in
// its original format unless the request specifies a value for the tfmt
// parameter and in its original language unless the request specifies a
// value for the tlang parameter.
func (r *CaptionsService) Download(id string) *CaptionsDownloadCall {
	c := &CaptionsDownloadCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOf sets the optional parameter "onBehalfOf": ID of the
// Google+ Page for the channel that the request is be on behalf of
func (c *CaptionsDownloadCall) OnBehalfOf(onBehalfOf string) *CaptionsDownloadCall {
	c.opt_["onBehalfOf"] = onBehalfOf
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *CaptionsDownloadCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *CaptionsDownloadCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Tfmt sets the optional parameter "tfmt": The tfmt parameter specifies
// that the caption track should be returned in a specific format. If
// the parameter is not included in the request, the track is returned
// in its original format.
//
// Possible values:
//   "sbv" - SubViewer subtitle.
//   "scc" - Scenarist Closed Caption format.
//   "srt" - SubRip subtitle.
//   "ttml" - Timed Text Markup Language caption.
//   "vtt" - Web Video Text Tracks caption.
func (c *CaptionsDownloadCall) Tfmt(tfmt string) *CaptionsDownloadCall {
	c.opt_["tfmt"] = tfmt
	return c
}

// Tlang sets the optional parameter "tlang": The tlang parameter
// specifies that the API response should return a translation of the
// specified caption track. The parameter value is an ISO 639-1
// two-letter language code that identifies the desired caption
// language. The translation is generated by using machine translation,
// such as Google Translate.
func (c *CaptionsDownloadCall) Tlang(tlang string) *CaptionsDownloadCall {
	c.opt_["tlang"] = tlang
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CaptionsDownloadCall) Fields(s ...googleapi.Field) *CaptionsDownloadCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CaptionsDownloadCall) IfNoneMatch(entityTag string) *CaptionsDownloadCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CaptionsDownloadCall) Context(ctx context.Context) *CaptionsDownloadCall {
	c.ctx_ = ctx
	return c
}

func (c *CaptionsDownloadCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["onBehalfOf"]; ok {
		params.Set("onBehalfOf", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["tfmt"]; ok {
		params.Set("tfmt", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["tlang"]; ok {
		params.Set("tlang", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "captions/{id}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"id": c.id,
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
func (c *CaptionsDownloadCall) Download() (*http.Response, error) {
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

// Do executes the "youtube.captions.download" call.
func (c *CaptionsDownloadCall) Do() error {
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
	//   "description": "Downloads a caption track. The caption track is returned in its original format unless the request specifies a value for the tfmt parameter and in its original language unless the request specifies a value for the tlang parameter.",
	//   "httpMethod": "GET",
	//   "id": "youtube.captions.download",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter identifies the caption track that is being retrieved. The value is a caption track ID as identified by the id property in a caption resource.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOf": {
	//       "description": "ID of the Google+ Page for the channel that the request is be on behalf of",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "tfmt": {
	//       "description": "The tfmt parameter specifies that the caption track should be returned in a specific format. If the parameter is not included in the request, the track is returned in its original format.",
	//       "enum": [
	//         "sbv",
	//         "scc",
	//         "srt",
	//         "ttml",
	//         "vtt"
	//       ],
	//       "enumDescriptions": [
	//         "SubViewer subtitle.",
	//         "Scenarist Closed Caption format.",
	//         "SubRip subtitle.",
	//         "Timed Text Markup Language caption.",
	//         "Web Video Text Tracks caption."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "tlang": {
	//       "description": "The tlang parameter specifies that the API response should return a translation of the specified caption track. The parameter value is an ISO 639-1 two-letter language code that identifies the desired caption language. The translation is generated by using machine translation, such as Google Translate.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "captions/{id}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaDownload": true
	// }

}

// method id "youtube.captions.insert":

type CaptionsInsertCall struct {
	s          *Service
	part       string
	caption    *Caption
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Insert: Uploads a caption track.
func (r *CaptionsService) Insert(part string, caption *Caption) *CaptionsInsertCall {
	c := &CaptionsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.caption = caption
	return c
}

// OnBehalfOf sets the optional parameter "onBehalfOf": ID of the
// Google+ Page for the channel that the request is be on behalf of
func (c *CaptionsInsertCall) OnBehalfOf(onBehalfOf string) *CaptionsInsertCall {
	c.opt_["onBehalfOf"] = onBehalfOf
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *CaptionsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *CaptionsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Sync sets the optional parameter "sync": The sync parameter indicates
// whether YouTube should automatically synchronize the caption file
// with the audio track of the video. If you set the value to true,
// YouTube will disregard any time codes that are in the uploaded
// caption file and generate new time codes for the captions.
//
// You should set the sync parameter to true if you are uploading a
// transcript, which has no time codes, or if you suspect the time codes
// in your file are incorrect and want YouTube to try to fix them.
func (c *CaptionsInsertCall) Sync(sync bool) *CaptionsInsertCall {
	c.opt_["sync"] = sync
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *CaptionsInsertCall) Media(r io.Reader) *CaptionsInsertCall {
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
func (c *CaptionsInsertCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *CaptionsInsertCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *CaptionsInsertCall) ProgressUpdater(pu googleapi.ProgressUpdater) *CaptionsInsertCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CaptionsInsertCall) Fields(s ...googleapi.Field) *CaptionsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *CaptionsInsertCall) Context(ctx context.Context) *CaptionsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *CaptionsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.caption)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOf"]; ok {
		params.Set("onBehalfOf", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sync"]; ok {
		params.Set("sync", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "captions")
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

// Do executes the "youtube.captions.insert" call.
// Exactly one of *Caption or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Caption.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CaptionsInsertCall) Do() (*Caption, error) {
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
	ret := &Caption{
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
	//   "description": "Uploads a caption track.",
	//   "httpMethod": "POST",
	//   "id": "youtube.captions.insert",
	//   "mediaUpload": {
	//     "accept": [
	//       "*/*",
	//       "application/octet-stream",
	//       "text/xml"
	//     ],
	//     "maxSize": "100MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/captions"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/captions"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOf": {
	//       "description": "ID of the Google+ Page for the channel that the request is be on behalf of",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the caption resource parts that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "sync": {
	//       "description": "The sync parameter indicates whether YouTube should automatically synchronize the caption file with the audio track of the video. If you set the value to true, YouTube will disregard any time codes that are in the uploaded caption file and generate new time codes for the captions.\n\nYou should set the sync parameter to true if you are uploading a transcript, which has no time codes, or if you suspect the time codes in your file are incorrect and want YouTube to try to fix them.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "captions",
	//   "request": {
	//     "$ref": "Caption"
	//   },
	//   "response": {
	//     "$ref": "Caption"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.captions.list":

type CaptionsListCall struct {
	s       *Service
	part    string
	videoId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// List: Returns a list of caption tracks that are associated with a
// specified video. Note that the API response does not contain the
// actual captions and that the captions.download method provides the
// ability to retrieve a caption track.
func (r *CaptionsService) List(part string, videoId string) *CaptionsListCall {
	c := &CaptionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.videoId = videoId
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of IDs that identify the caption resources that
// should be retrieved. Each ID must identify a caption track associated
// with the specified video.
func (c *CaptionsListCall) Id(id string) *CaptionsListCall {
	c.opt_["id"] = id
	return c
}

// OnBehalfOf sets the optional parameter "onBehalfOf": ID of the
// Google+ Page for the channel that the request is on behalf of.
func (c *CaptionsListCall) OnBehalfOf(onBehalfOf string) *CaptionsListCall {
	c.opt_["onBehalfOf"] = onBehalfOf
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *CaptionsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *CaptionsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CaptionsListCall) Fields(s ...googleapi.Field) *CaptionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CaptionsListCall) IfNoneMatch(entityTag string) *CaptionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CaptionsListCall) Context(ctx context.Context) *CaptionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *CaptionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	params.Set("videoId", fmt.Sprintf("%v", c.videoId))
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOf"]; ok {
		params.Set("onBehalfOf", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "captions")
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

// Do executes the "youtube.captions.list" call.
// Exactly one of *CaptionListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CaptionListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CaptionsListCall) Do() (*CaptionListResponse, error) {
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
	ret := &CaptionListResponse{
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
	//   "description": "Returns a list of caption tracks that are associated with a specified video. Note that the API response does not contain the actual captions and that the captions.download method provides the ability to retrieve a caption track.",
	//   "httpMethod": "GET",
	//   "id": "youtube.captions.list",
	//   "parameterOrder": [
	//     "part",
	//     "videoId"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of IDs that identify the caption resources that should be retrieved. Each ID must identify a caption track associated with the specified video.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOf": {
	//       "description": "ID of the Google+ Page for the channel that the request is on behalf of.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more caption resource parts that the API response will include. The part names that you can include in the parameter value are id and snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "The videoId parameter specifies the YouTube video ID of the video for which the API should return caption tracks.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "captions",
	//   "response": {
	//     "$ref": "CaptionListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.captions.update":

type CaptionsUpdateCall struct {
	s          *Service
	part       string
	caption    *Caption
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Update: Updates a caption track. When updating a caption track, you
// can change the track's draft status, upload a new caption file for
// the track, or both.
func (r *CaptionsService) Update(part string, caption *Caption) *CaptionsUpdateCall {
	c := &CaptionsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.caption = caption
	return c
}

// OnBehalfOf sets the optional parameter "onBehalfOf": ID of the
// Google+ Page for the channel that the request is be on behalf of
func (c *CaptionsUpdateCall) OnBehalfOf(onBehalfOf string) *CaptionsUpdateCall {
	c.opt_["onBehalfOf"] = onBehalfOf
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *CaptionsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *CaptionsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Sync sets the optional parameter "sync": Note: The API server only
// processes the parameter value if the request contains an updated
// caption file.
//
// The sync parameter indicates whether YouTube should automatically
// synchronize the caption file with the audio track of the video. If
// you set the value to true, YouTube will automatically synchronize the
// caption track with the audio track.
func (c *CaptionsUpdateCall) Sync(sync bool) *CaptionsUpdateCall {
	c.opt_["sync"] = sync
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *CaptionsUpdateCall) Media(r io.Reader) *CaptionsUpdateCall {
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
func (c *CaptionsUpdateCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *CaptionsUpdateCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *CaptionsUpdateCall) ProgressUpdater(pu googleapi.ProgressUpdater) *CaptionsUpdateCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CaptionsUpdateCall) Fields(s ...googleapi.Field) *CaptionsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *CaptionsUpdateCall) Context(ctx context.Context) *CaptionsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *CaptionsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.caption)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOf"]; ok {
		params.Set("onBehalfOf", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sync"]; ok {
		params.Set("sync", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "captions")
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

// Do executes the "youtube.captions.update" call.
// Exactly one of *Caption or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Caption.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CaptionsUpdateCall) Do() (*Caption, error) {
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
	ret := &Caption{
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
	//   "description": "Updates a caption track. When updating a caption track, you can change the track's draft status, upload a new caption file for the track, or both.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.captions.update",
	//   "mediaUpload": {
	//     "accept": [
	//       "*/*",
	//       "application/octet-stream",
	//       "text/xml"
	//     ],
	//     "maxSize": "100MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/captions"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/captions"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOf": {
	//       "description": "ID of the Google+ Page for the channel that the request is be on behalf of",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include. Set the property value to snippet if you are updating the track's draft status. Otherwise, set the property value to id.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "sync": {
	//       "description": "Note: The API server only processes the parameter value if the request contains an updated caption file.\n\nThe sync parameter indicates whether YouTube should automatically synchronize the caption file with the audio track of the video. If you set the value to true, YouTube will automatically synchronize the caption track with the audio track.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "captions",
	//   "request": {
	//     "$ref": "Caption"
	//   },
	//   "response": {
	//     "$ref": "Caption"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.channelBanners.insert":

type ChannelBannersInsertCall struct {
	s                     *Service
	channelbannerresource *ChannelBannerResource
	opt_                  map[string]interface{}
	media_                io.Reader
	resumable_            googleapi.SizeReaderAt
	mediaType_            string
	protocol_             string
	ctx_                  context.Context
}

// Insert: Uploads a channel banner image to YouTube. This method
// represents the first two steps in a three-step process to update the
// banner image for a channel:
//
// - Call the channelBanners.insert method to upload the binary image
// data to YouTube. The image must have a 16:9 aspect ratio and be at
// least 2120x1192 pixels.
// - Extract the url property's value from the response that the API
// returns for step 1.
// - Call the channels.update method to update the channel's branding
// settings. Set the brandingSettings.image.bannerExternalUrl property's
// value to the URL obtained in step 2.
func (r *ChannelBannersService) Insert(channelbannerresource *ChannelBannerResource) *ChannelBannersInsertCall {
	c := &ChannelBannersInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.channelbannerresource = channelbannerresource
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelBannersInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelBannersInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *ChannelBannersInsertCall) Media(r io.Reader) *ChannelBannersInsertCall {
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
func (c *ChannelBannersInsertCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *ChannelBannersInsertCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *ChannelBannersInsertCall) ProgressUpdater(pu googleapi.ProgressUpdater) *ChannelBannersInsertCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelBannersInsertCall) Fields(s ...googleapi.Field) *ChannelBannersInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *ChannelBannersInsertCall) Context(ctx context.Context) *ChannelBannersInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelBannersInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channelbannerresource)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channelBanners/insert")
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

// Do executes the "youtube.channelBanners.insert" call.
// Exactly one of *ChannelBannerResource or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ChannelBannerResource.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChannelBannersInsertCall) Do() (*ChannelBannerResource, error) {
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
	ret := &ChannelBannerResource{
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
	//   "description": "Uploads a channel banner image to YouTube. This method represents the first two steps in a three-step process to update the banner image for a channel:\n\n- Call the channelBanners.insert method to upload the binary image data to YouTube. The image must have a 16:9 aspect ratio and be at least 2120x1192 pixels.\n- Extract the url property's value from the response that the API returns for step 1.\n- Call the channels.update method to update the channel's branding settings. Set the brandingSettings.image.bannerExternalUrl property's value to the URL obtained in step 2.",
	//   "httpMethod": "POST",
	//   "id": "youtube.channelBanners.insert",
	//   "mediaUpload": {
	//     "accept": [
	//       "application/octet-stream",
	//       "image/jpeg",
	//       "image/png"
	//     ],
	//     "maxSize": "6MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/channelBanners/insert"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/channelBanners/insert"
	//       }
	//     }
	//   },
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "channelBanners/insert",
	//   "request": {
	//     "$ref": "ChannelBannerResource"
	//   },
	//   "response": {
	//     "$ref": "ChannelBannerResource"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.upload"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.channelSections.delete":

type ChannelSectionsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a channelSection.
func (r *ChannelSectionsService) Delete(id string) *ChannelSectionsDeleteCall {
	c := &ChannelSectionsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelSectionsDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelSectionsDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelSectionsDeleteCall) Fields(s ...googleapi.Field) *ChannelSectionsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelSectionsDeleteCall) Context(ctx context.Context) *ChannelSectionsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelSectionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channelSections")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.channelSections.delete" call.
func (c *ChannelSectionsDeleteCall) Do() error {
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
	//   "description": "Deletes a channelSection.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.channelSections.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube channelSection ID for the resource that is being deleted. In a channelSection resource, the id property specifies the YouTube channelSection ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "channelSections",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.channelSections.insert":

type ChannelSectionsInsertCall struct {
	s              *Service
	part           string
	channelsection *ChannelSection
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Insert: Adds a channelSection for the authenticated user's channel.
func (r *ChannelSectionsService) Insert(part string, channelsection *ChannelSection) *ChannelSectionsInsertCall {
	c := &ChannelSectionsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.channelsection = channelsection
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelSectionsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelSectionsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *ChannelSectionsInsertCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *ChannelSectionsInsertCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelSectionsInsertCall) Fields(s ...googleapi.Field) *ChannelSectionsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelSectionsInsertCall) Context(ctx context.Context) *ChannelSectionsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelSectionsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channelsection)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channelSections")
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

// Do executes the "youtube.channelSections.insert" call.
// Exactly one of *ChannelSection or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChannelSection.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChannelSectionsInsertCall) Do() (*ChannelSection, error) {
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
	ret := &ChannelSection{
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
	//   "description": "Adds a channelSection for the authenticated user's channel.",
	//   "httpMethod": "POST",
	//   "id": "youtube.channelSections.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part names that you can include in the parameter value are snippet and contentDetails.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "channelSections",
	//   "request": {
	//     "$ref": "ChannelSection"
	//   },
	//   "response": {
	//     "$ref": "ChannelSection"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.channelSections.list":

type ChannelSectionsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns channelSection resources that match the API request
// criteria.
func (r *ChannelSectionsService) List(part string) *ChannelSectionsListCall {
	c := &ChannelSectionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// ChannelId sets the optional parameter "channelId": The channelId
// parameter specifies a YouTube channel ID. The API will only return
// that channel's channelSections.
func (c *ChannelSectionsListCall) ChannelId(channelId string) *ChannelSectionsListCall {
	c.opt_["channelId"] = channelId
	return c
}

// Hl sets the optional parameter "hl": The hl parameter indicates that
// the snippet.localized property values in the returned channelSection
// resources should be in the specified language if localized values for
// that language are available. For example, if the API request
// specifies hl=de, the snippet.localized properties in the API response
// will contain German titles if German titles are available. Channel
// owners can provide localized channel section titles using either the
// channelSections.insert or channelSections.update method.
func (c *ChannelSectionsListCall) Hl(hl string) *ChannelSectionsListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube channelSection ID(s) for the
// resource(s) that are being retrieved. In a channelSection resource,
// the id property specifies the YouTube channelSection ID.
func (c *ChannelSectionsListCall) Id(id string) *ChannelSectionsListCall {
	c.opt_["id"] = id
	return c
}

// Mine sets the optional parameter "mine": Set this parameter's value
// to true to retrieve a feed of the authenticated user's
// channelSections.
func (c *ChannelSectionsListCall) Mine(mine bool) *ChannelSectionsListCall {
	c.opt_["mine"] = mine
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelSectionsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelSectionsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelSectionsListCall) Fields(s ...googleapi.Field) *ChannelSectionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChannelSectionsListCall) IfNoneMatch(entityTag string) *ChannelSectionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelSectionsListCall) Context(ctx context.Context) *ChannelSectionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelSectionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channelSections")
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

// Do executes the "youtube.channelSections.list" call.
// Exactly one of *ChannelSectionListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ChannelSectionListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChannelSectionsListCall) Do() (*ChannelSectionListResponse, error) {
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
	ret := &ChannelSectionListResponse{
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
	//   "description": "Returns channelSection resources that match the API request criteria.",
	//   "httpMethod": "GET",
	//   "id": "youtube.channelSections.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter specifies a YouTube channel ID. The API will only return that channel's channelSections.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "hl": {
	//       "description": "The hl parameter indicates that the snippet.localized property values in the returned channelSection resources should be in the specified language if localized values for that language are available. For example, if the API request specifies hl=de, the snippet.localized properties in the API response will contain German titles if German titles are available. Channel owners can provide localized channel section titles using either the channelSections.insert or channelSections.update method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube channelSection ID(s) for the resource(s) that are being retrieved. In a channelSection resource, the id property specifies the YouTube channelSection ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "mine": {
	//       "description": "Set this parameter's value to true to retrieve a feed of the authenticated user's channelSections.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more channelSection resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, and contentDetails.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a channelSection resource, the snippet property contains other properties, such as a display title for the channelSection. If you set part=snippet, the API response will also contain all of those nested properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "channelSections",
	//   "response": {
	//     "$ref": "ChannelSectionListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.channelSections.update":

type ChannelSectionsUpdateCall struct {
	s              *Service
	part           string
	channelsection *ChannelSection
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Update a channelSection.
func (r *ChannelSectionsService) Update(part string, channelsection *ChannelSection) *ChannelSectionsUpdateCall {
	c := &ChannelSectionsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.channelsection = channelsection
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelSectionsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelSectionsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelSectionsUpdateCall) Fields(s ...googleapi.Field) *ChannelSectionsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelSectionsUpdateCall) Context(ctx context.Context) *ChannelSectionsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelSectionsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channelsection)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channelSections")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.channelSections.update" call.
// Exactly one of *ChannelSection or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChannelSection.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChannelSectionsUpdateCall) Do() (*ChannelSection, error) {
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
	ret := &ChannelSection{
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
	//   "description": "Update a channelSection.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.channelSections.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part names that you can include in the parameter value are snippet and contentDetails.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "channelSections",
	//   "request": {
	//     "$ref": "ChannelSection"
	//   },
	//   "response": {
	//     "$ref": "ChannelSection"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.channels.list":

type ChannelsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a collection of zero or more channel resources that
// match the request criteria.
func (r *ChannelsService) List(part string) *ChannelsListCall {
	c := &ChannelsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// CategoryId sets the optional parameter "categoryId": The categoryId
// parameter specifies a YouTube guide category, thereby requesting
// YouTube channels associated with that category.
func (c *ChannelsListCall) CategoryId(categoryId string) *ChannelsListCall {
	c.opt_["categoryId"] = categoryId
	return c
}

// ForUsername sets the optional parameter "forUsername": The
// forUsername parameter specifies a YouTube username, thereby
// requesting the channel associated with that username.
func (c *ChannelsListCall) ForUsername(forUsername string) *ChannelsListCall {
	c.opt_["forUsername"] = forUsername
	return c
}

// Hl sets the optional parameter "hl": The hl parameter should be used
// for filter out the properties that are not in the given language.
// Used for the brandingSettings part.
func (c *ChannelsListCall) Hl(hl string) *ChannelsListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube channel ID(s) for the resource(s)
// that are being retrieved. In a channel resource, the id property
// specifies the channel's YouTube channel ID.
func (c *ChannelsListCall) Id(id string) *ChannelsListCall {
	c.opt_["id"] = id
	return c
}

// ManagedByMe sets the optional parameter "managedByMe": Note: This
// parameter is intended exclusively for YouTube content partners.
//
// Set this parameter's value to true to instruct the API to only return
// channels managed by the content owner that the onBehalfOfContentOwner
// parameter specifies. The user must be authenticated as a CMS account
// linked to the specified content owner and onBehalfOfContentOwner must
// be provided.
func (c *ChannelsListCall) ManagedByMe(managedByMe bool) *ChannelsListCall {
	c.opt_["managedByMe"] = managedByMe
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *ChannelsListCall) MaxResults(maxResults int64) *ChannelsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": Set this parameter's value
// to true to instruct the API to only return channels owned by the
// authenticated user.
func (c *ChannelsListCall) Mine(mine bool) *ChannelsListCall {
	c.opt_["mine"] = mine
	return c
}

// MySubscribers sets the optional parameter "mySubscribers": Use the
// subscriptions.list method and its mySubscribers parameter to retrieve
// a list of subscribers to the authenticated user's channel.
func (c *ChannelsListCall) MySubscribers(mySubscribers bool) *ChannelsListCall {
	c.opt_["mySubscribers"] = mySubscribers
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *ChannelsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *ChannelsListCall) PageToken(pageToken string) *ChannelsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelsListCall) Fields(s ...googleapi.Field) *ChannelsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChannelsListCall) IfNoneMatch(entityTag string) *ChannelsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelsListCall) Context(ctx context.Context) *ChannelsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["categoryId"]; ok {
		params.Set("categoryId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["forUsername"]; ok {
		params.Set("forUsername", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["managedByMe"]; ok {
		params.Set("managedByMe", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mySubscribers"]; ok {
		params.Set("mySubscribers", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channels")
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

// Do executes the "youtube.channels.list" call.
// Exactly one of *ChannelListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ChannelListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChannelsListCall) Do() (*ChannelListResponse, error) {
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
	ret := &ChannelListResponse{
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
	//   "description": "Returns a collection of zero or more channel resources that match the request criteria.",
	//   "httpMethod": "GET",
	//   "id": "youtube.channels.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "categoryId": {
	//       "description": "The categoryId parameter specifies a YouTube guide category, thereby requesting YouTube channels associated with that category.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "forUsername": {
	//       "description": "The forUsername parameter specifies a YouTube username, thereby requesting the channel associated with that username.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "hl": {
	//       "description": "The hl parameter should be used for filter out the properties that are not in the given language. Used for the brandingSettings part.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube channel ID(s) for the resource(s) that are being retrieved. In a channel resource, the id property specifies the channel's YouTube channel ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "managedByMe": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nSet this parameter's value to true to instruct the API to only return channels managed by the content owner that the onBehalfOfContentOwner parameter specifies. The user must be authenticated as a CMS account linked to the specified content owner and onBehalfOfContentOwner must be provided.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "Set this parameter's value to true to instruct the API to only return channels owned by the authenticated user.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "mySubscribers": {
	//       "description": "Use the subscriptions.list method and its mySubscribers parameter to retrieve a list of subscribers to the authenticated user's channel.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more channel resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a channel resource, the contentDetails property contains other properties, such as the uploads properties. As such, if you set part=contentDetails, the API response will also contain all of those nested properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "channels",
	//   "response": {
	//     "$ref": "ChannelListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner",
	//     "https://www.googleapis.com/auth/youtubepartner-channel-audit"
	//   ]
	// }

}

// method id "youtube.channels.update":

type ChannelsUpdateCall struct {
	s       *Service
	part    string
	channel *Channel
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Update: Updates a channel's metadata. Note that this method currently
// only supports updates to the channel resource's brandingSettings and
// invideoPromotion objects and their child properties.
func (r *ChannelsService) Update(part string, channel *Channel) *ChannelsUpdateCall {
	c := &ChannelsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.channel = channel
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": The onBehalfOfContentOwner parameter
// indicates that the authenticated user is acting on behalf of the
// content owner specified in the parameter value. This parameter is
// intended for YouTube content partners that own and manage many
// different YouTube channels. It allows content owners to authenticate
// once and get access to all their video and channel data, without
// having to provide authentication credentials for each individual
// channel. The actual CMS account that the user authenticates with
// needs to be linked to the specified YouTube content owner.
func (c *ChannelsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ChannelsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelsUpdateCall) Fields(s ...googleapi.Field) *ChannelsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelsUpdateCall) Context(ctx context.Context) *ChannelsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channel)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channels")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.channels.update" call.
// Exactly one of *Channel or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Channel.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ChannelsUpdateCall) Do() (*Channel, error) {
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
	//   "description": "Updates a channel's metadata. Note that this method currently only supports updates to the channel resource's brandingSettings and invideoPromotion objects and their child properties.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.channels.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "The onBehalfOfContentOwner parameter indicates that the authenticated user is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with needs to be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe API currently only allows the parameter value to be set to either brandingSettings or invideoPromotion. (You cannot update both of those parts with a single request.)\n\nNote that this method overrides the existing values for all of the mutable properties that are contained in any parts that the parameter value specifies.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "channels",
	//   "request": {
	//     "$ref": "Channel"
	//   },
	//   "response": {
	//     "$ref": "Channel"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.commentThreads.insert":

type CommentThreadsInsertCall struct {
	s             *Service
	part          string
	commentthread *CommentThread
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Creates a new top-level comment. To add a reply to an
// existing comment, use the comments.insert method instead.
func (r *CommentThreadsService) Insert(part string, commentthread *CommentThread) *CommentThreadsInsertCall {
	c := &CommentThreadsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.commentthread = commentthread
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentThreadsInsertCall) Fields(s ...googleapi.Field) *CommentThreadsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentThreadsInsertCall) Context(ctx context.Context) *CommentThreadsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentThreadsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.commentthread)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "commentThreads")
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

// Do executes the "youtube.commentThreads.insert" call.
// Exactly one of *CommentThread or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentThread.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CommentThreadsInsertCall) Do() (*CommentThread, error) {
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
	ret := &CommentThread{
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
	//   "description": "Creates a new top-level comment. To add a reply to an existing comment, use the comments.insert method instead.",
	//   "httpMethod": "POST",
	//   "id": "youtube.commentThreads.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter identifies the properties that the API response will include. Set the parameter value to snippet. The snippet part has a quota cost of 2 units.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "commentThreads",
	//   "request": {
	//     "$ref": "CommentThread"
	//   },
	//   "response": {
	//     "$ref": "CommentThread"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.commentThreads.list":

type CommentThreadsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of comment threads that match the API request
// parameters.
func (r *CommentThreadsService) List(part string) *CommentThreadsListCall {
	c := &CommentThreadsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// AllThreadsRelatedToChannelId sets the optional parameter
// "allThreadsRelatedToChannelId": The allThreadsRelatedToChannelId
// parameter instructs the API to return all comment threads associated
// with the specified channel. The response can include comments about
// the channel or about the channel's videos.
func (c *CommentThreadsListCall) AllThreadsRelatedToChannelId(allThreadsRelatedToChannelId string) *CommentThreadsListCall {
	c.opt_["allThreadsRelatedToChannelId"] = allThreadsRelatedToChannelId
	return c
}

// ChannelId sets the optional parameter "channelId": The channelId
// parameter instructs the API to return comment threads containing
// comments about the specified channel. (The response will not include
// comments left on videos that the channel uploaded.)
func (c *CommentThreadsListCall) ChannelId(channelId string) *CommentThreadsListCall {
	c.opt_["channelId"] = channelId
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of comment thread IDs for the resources that
// should be retrieved.
func (c *CommentThreadsListCall) Id(id string) *CommentThreadsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
func (c *CommentThreadsListCall) MaxResults(maxResults int64) *CommentThreadsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// ModerationStatus sets the optional parameter "moderationStatus": Set
// this parameter to limit the returned comment threads to a particular
// moderation state.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
//
// Possible values:
//   "heldForReview" - Retrieve comment threads that are awaiting review
// by a moderator. A comment thread can be included in the response if
// the top-level comment or at least one of the replies to that comment
// are awaiting review.
//   "likelySpam" - Retrieve comment threads classified as likely to be
// spam. A comment thread can be included in the response if the
// top-level comment or at least one of the replies to that comment is
// considered likely to be spam.
//   "published" - Retrieve threads of published comments. This is the
// default value. A comment thread can be included in the response if
// its top-level comment has been published.
func (c *CommentThreadsListCall) ModerationStatus(moderationStatus string) *CommentThreadsListCall {
	c.opt_["moderationStatus"] = moderationStatus
	return c
}

// Order sets the optional parameter "order": The order parameter
// specifies the order in which the API response should list comment
// threads. Valid values are:
// - time - Comment threads are ordered by time. This is the default
// behavior.
// - relevance - Comment threads are ordered by relevance.Note: This
// parameter is not supported for use in conjunction with the id
// parameter.
//
// Possible values:
//   "relevance" - Order by relevance.
//   "time" - Order by time.
func (c *CommentThreadsListCall) Order(order string) *CommentThreadsListCall {
	c.opt_["order"] = order
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken property identifies
// the next page of the result that can be retrieved.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
func (c *CommentThreadsListCall) PageToken(pageToken string) *CommentThreadsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// SearchTerms sets the optional parameter "searchTerms": The
// searchTerms parameter instructs the API to limit the API response to
// only contain comments that contain the specified search terms.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
func (c *CommentThreadsListCall) SearchTerms(searchTerms string) *CommentThreadsListCall {
	c.opt_["searchTerms"] = searchTerms
	return c
}

// TextFormat sets the optional parameter "textFormat": Set this
// parameter's value to html or plainText to instruct the API to return
// the comments left by users in html formatted or in plain text.
//
// Possible values:
//   "html" - Returns the comments in HTML format. This is the default
// value.
//   "plainText" - Returns the comments in plain text format.
func (c *CommentThreadsListCall) TextFormat(textFormat string) *CommentThreadsListCall {
	c.opt_["textFormat"] = textFormat
	return c
}

// VideoId sets the optional parameter "videoId": The videoId parameter
// instructs the API to return comment threads associated with the
// specified video ID.
func (c *CommentThreadsListCall) VideoId(videoId string) *CommentThreadsListCall {
	c.opt_["videoId"] = videoId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentThreadsListCall) Fields(s ...googleapi.Field) *CommentThreadsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CommentThreadsListCall) IfNoneMatch(entityTag string) *CommentThreadsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentThreadsListCall) Context(ctx context.Context) *CommentThreadsListCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentThreadsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["allThreadsRelatedToChannelId"]; ok {
		params.Set("allThreadsRelatedToChannelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["moderationStatus"]; ok {
		params.Set("moderationStatus", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["order"]; ok {
		params.Set("order", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["searchTerms"]; ok {
		params.Set("searchTerms", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["textFormat"]; ok {
		params.Set("textFormat", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoId"]; ok {
		params.Set("videoId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "commentThreads")
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

// Do executes the "youtube.commentThreads.list" call.
// Exactly one of *CommentThreadListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *CommentThreadListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CommentThreadsListCall) Do() (*CommentThreadListResponse, error) {
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
	ret := &CommentThreadListResponse{
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
	//   "description": "Returns a list of comment threads that match the API request parameters.",
	//   "httpMethod": "GET",
	//   "id": "youtube.commentThreads.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "allThreadsRelatedToChannelId": {
	//       "description": "The allThreadsRelatedToChannelId parameter instructs the API to return all comment threads associated with the specified channel. The response can include comments about the channel or about the channel's videos.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "channelId": {
	//       "description": "The channelId parameter instructs the API to return comment threads containing comments about the specified channel. (The response will not include comments left on videos that the channel uploaded.)",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of comment thread IDs for the resources that should be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "moderationStatus": {
	//       "default": "MODERATION_STATUS_PUBLISHED",
	//       "description": "Set this parameter to limit the returned comment threads to a particular moderation state.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "enum": [
	//         "heldForReview",
	//         "likelySpam",
	//         "published"
	//       ],
	//       "enumDescriptions": [
	//         "Retrieve comment threads that are awaiting review by a moderator. A comment thread can be included in the response if the top-level comment or at least one of the replies to that comment are awaiting review.",
	//         "Retrieve comment threads classified as likely to be spam. A comment thread can be included in the response if the top-level comment or at least one of the replies to that comment is considered likely to be spam.",
	//         "Retrieve threads of published comments. This is the default value. A comment thread can be included in the response if its top-level comment has been published."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "order": {
	//       "default": "true",
	//       "description": "The order parameter specifies the order in which the API response should list comment threads. Valid values are: \n- time - Comment threads are ordered by time. This is the default behavior.\n- relevance - Comment threads are ordered by relevance.Note: This parameter is not supported for use in conjunction with the id parameter.",
	//       "enum": [
	//         "relevance",
	//         "time"
	//       ],
	//       "enumDescriptions": [
	//         "Order by relevance.",
	//         "Order by time."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken property identifies the next page of the result that can be retrieved.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more commentThread resource properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "searchTerms": {
	//       "description": "The searchTerms parameter instructs the API to limit the API response to only contain comments that contain the specified search terms.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "textFormat": {
	//       "default": "FORMAT_HTML",
	//       "description": "Set this parameter's value to html or plainText to instruct the API to return the comments left by users in html formatted or in plain text.",
	//       "enum": [
	//         "html",
	//         "plainText"
	//       ],
	//       "enumDescriptions": [
	//         "Returns the comments in HTML format. This is the default value.",
	//         "Returns the comments in plain text format."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "The videoId parameter instructs the API to return comment threads associated with the specified video ID.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "commentThreads",
	//   "response": {
	//     "$ref": "CommentThreadListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.commentThreads.update":

type CommentThreadsUpdateCall struct {
	s             *Service
	part          string
	commentthread *CommentThread
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Modifies the top-level comment in a comment thread.
func (r *CommentThreadsService) Update(part string, commentthread *CommentThread) *CommentThreadsUpdateCall {
	c := &CommentThreadsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.commentthread = commentthread
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentThreadsUpdateCall) Fields(s ...googleapi.Field) *CommentThreadsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentThreadsUpdateCall) Context(ctx context.Context) *CommentThreadsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentThreadsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.commentthread)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "commentThreads")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.commentThreads.update" call.
// Exactly one of *CommentThread or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentThread.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CommentThreadsUpdateCall) Do() (*CommentThread, error) {
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
	ret := &CommentThread{
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
	//   "description": "Modifies the top-level comment in a comment thread.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.commentThreads.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of commentThread resource properties that the API response will include. You must at least include the snippet part in the parameter value since that part contains all of the properties that the API request can update.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "commentThreads",
	//   "request": {
	//     "$ref": "CommentThread"
	//   },
	//   "response": {
	//     "$ref": "CommentThread"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.delete":

type CommentsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a comment.
func (r *CommentsService) Delete(id string) *CommentsDeleteCall {
	c := &CommentsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
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
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.comments.delete" call.
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
	//   "id": "youtube.comments.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the comment ID for the resource that is being deleted.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.insert":

type CommentsInsertCall struct {
	s       *Service
	part    string
	comment *Comment
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Insert: Creates a reply to an existing comment. Note: To create a
// top-level comment, use the commentThreads.insert method.
func (r *CommentsService) Insert(part string, comment *Comment) *CommentsInsertCall {
	c := &CommentsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
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
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments")
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

// Do executes the "youtube.comments.insert" call.
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
	//   "description": "Creates a reply to an existing comment. Note: To create a top-level comment, use the commentThreads.insert method.",
	//   "httpMethod": "POST",
	//   "id": "youtube.comments.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter identifies the properties that the API response will include. Set the parameter value to snippet. The snippet part has a quota cost of 2 units.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.list":

type CommentsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of comments that match the API request
// parameters.
func (r *CommentsService) List(part string) *CommentsListCall {
	c := &CommentsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of comment IDs for the resources that are being
// retrieved. In a comment resource, the id property specifies the
// comment's ID.
func (c *CommentsListCall) Id(id string) *CommentsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
func (c *CommentsListCall) MaxResults(maxResults int64) *CommentsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken property identifies
// the next page of the result that can be retrieved.
//
// Note: This parameter is not supported for use in conjunction with the
// id parameter.
func (c *CommentsListCall) PageToken(pageToken string) *CommentsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// ParentId sets the optional parameter "parentId": The parentId
// parameter specifies the ID of the comment for which replies should be
// retrieved.
//
// Note: YouTube currently supports replies only for top-level comments.
// However, replies to replies may be supported in the future.
func (c *CommentsListCall) ParentId(parentId string) *CommentsListCall {
	c.opt_["parentId"] = parentId
	return c
}

// TextFormat sets the optional parameter "textFormat": This parameter
// indicates whether the API should return comments formatted as HTML or
// as plain text.
//
// Possible values:
//   "html" - Returns the comments in HTML format. This is the default
// value.
//   "plainText" - Returns the comments in plain text format.
func (c *CommentsListCall) TextFormat(textFormat string) *CommentsListCall {
	c.opt_["textFormat"] = textFormat
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
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["parentId"]; ok {
		params.Set("parentId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["textFormat"]; ok {
		params.Set("textFormat", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments")
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

// Do executes the "youtube.comments.list" call.
// Exactly one of *CommentListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CommentListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CommentsListCall) Do() (*CommentListResponse, error) {
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
	ret := &CommentListResponse{
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
	//   "description": "Returns a list of comments that match the API request parameters.",
	//   "httpMethod": "GET",
	//   "id": "youtube.comments.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of comment IDs for the resources that are being retrieved. In a comment resource, the id property specifies the comment's ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken property identifies the next page of the result that can be retrieved.\n\nNote: This parameter is not supported for use in conjunction with the id parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parentId": {
	//       "description": "The parentId parameter specifies the ID of the comment for which replies should be retrieved.\n\nNote: YouTube currently supports replies only for top-level comments. However, replies to replies may be supported in the future.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more comment resource properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "textFormat": {
	//       "default": "FORMAT_HTML",
	//       "description": "This parameter indicates whether the API should return comments formatted as HTML or as plain text.",
	//       "enum": [
	//         "html",
	//         "plainText"
	//       ],
	//       "enumDescriptions": [
	//         "Returns the comments in HTML format. This is the default value.",
	//         "Returns the comments in plain text format."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments",
	//   "response": {
	//     "$ref": "CommentListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.markAsSpam":

type CommentsMarkAsSpamCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// MarkAsSpam: Expresses the caller's opinion that one or more comments
// should be flagged as spam.
func (r *CommentsService) MarkAsSpam(id string) *CommentsMarkAsSpamCall {
	c := &CommentsMarkAsSpamCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsMarkAsSpamCall) Fields(s ...googleapi.Field) *CommentsMarkAsSpamCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsMarkAsSpamCall) Context(ctx context.Context) *CommentsMarkAsSpamCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsMarkAsSpamCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments/markAsSpam")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.comments.markAsSpam" call.
func (c *CommentsMarkAsSpamCall) Do() error {
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
	//   "description": "Expresses the caller's opinion that one or more comments should be flagged as spam.",
	//   "httpMethod": "POST",
	//   "id": "youtube.comments.markAsSpam",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of IDs of comments that the caller believes should be classified as spam.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments/markAsSpam",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.setModerationStatus":

type CommentsSetModerationStatusCall struct {
	s                *Service
	id               string
	moderationStatus string
	opt_             map[string]interface{}
	ctx_             context.Context
}

// SetModerationStatus: Sets the moderation status of one or more
// comments. The API request must be authorized by the owner of the
// channel or video associated with the comments.
func (r *CommentsService) SetModerationStatus(id string, moderationStatus string) *CommentsSetModerationStatusCall {
	c := &CommentsSetModerationStatusCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	c.moderationStatus = moderationStatus
	return c
}

// BanAuthor sets the optional parameter "banAuthor": The banAuthor
// parameter lets you indicate that you want to automatically reject any
// additional comments written by the comment's author. Set the
// parameter value to true to ban the author.
//
// Note: This parameter is only valid if the moderationStatus parameter
// is also set to rejected.
func (c *CommentsSetModerationStatusCall) BanAuthor(banAuthor bool) *CommentsSetModerationStatusCall {
	c.opt_["banAuthor"] = banAuthor
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsSetModerationStatusCall) Fields(s ...googleapi.Field) *CommentsSetModerationStatusCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsSetModerationStatusCall) Context(ctx context.Context) *CommentsSetModerationStatusCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsSetModerationStatusCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("moderationStatus", fmt.Sprintf("%v", c.moderationStatus))
	if v, ok := c.opt_["banAuthor"]; ok {
		params.Set("banAuthor", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments/setModerationStatus")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.comments.setModerationStatus" call.
func (c *CommentsSetModerationStatusCall) Do() error {
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
	//   "description": "Sets the moderation status of one or more comments. The API request must be authorized by the owner of the channel or video associated with the comments.",
	//   "httpMethod": "POST",
	//   "id": "youtube.comments.setModerationStatus",
	//   "parameterOrder": [
	//     "id",
	//     "moderationStatus"
	//   ],
	//   "parameters": {
	//     "banAuthor": {
	//       "default": "false",
	//       "description": "The banAuthor parameter lets you indicate that you want to automatically reject any additional comments written by the comment's author. Set the parameter value to true to ban the author.\n\nNote: This parameter is only valid if the moderationStatus parameter is also set to rejected.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of IDs that identify the comments for which you are updating the moderation status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "moderationStatus": {
	//       "description": "Identifies the new moderation status of the specified comments.",
	//       "enum": [
	//         "heldForReview",
	//         "published",
	//         "rejected"
	//       ],
	//       "enumDescriptions": [
	//         "Marks a comment as awaiting review by a moderator.",
	//         "Clears a comment for public display.",
	//         "Rejects a comment as being unfit for display. This action also effectively hides all replies to the rejected comment.\n\nNote: The API does not currently provide a way to list or otherwise discover rejected comments. However, you can change the moderation status of a rejected comment if you still know its ID. If you were to change the moderation status of a rejected comment, the comment replies would subsequently be discoverable again as well."
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments/setModerationStatus",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.comments.update":

type CommentsUpdateCall struct {
	s       *Service
	part    string
	comment *Comment
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Update: Modifies a comment.
func (r *CommentsService) Update(part string, comment *Comment) *CommentsUpdateCall {
	c := &CommentsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
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
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.comments.update" call.
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
	//   "description": "Modifies a comment.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.comments.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter identifies the properties that the API response will include. You must at least include the snippet part in the parameter value since that part contains all of the properties that the API request can update.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.guideCategories.list":

type GuideCategoriesListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of categories that can be associated with
// YouTube channels.
func (r *GuideCategoriesService) List(part string) *GuideCategoriesListCall {
	c := &GuideCategoriesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Hl sets the optional parameter "hl": The hl parameter specifies the
// language that will be used for text values in the API response.
func (c *GuideCategoriesListCall) Hl(hl string) *GuideCategoriesListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube channel category ID(s) for the
// resource(s) that are being retrieved. In a guideCategory resource,
// the id property specifies the YouTube channel category ID.
func (c *GuideCategoriesListCall) Id(id string) *GuideCategoriesListCall {
	c.opt_["id"] = id
	return c
}

// RegionCode sets the optional parameter "regionCode": The regionCode
// parameter instructs the API to return the list of guide categories
// available in the specified country. The parameter value is an ISO
// 3166-1 alpha-2 country code.
func (c *GuideCategoriesListCall) RegionCode(regionCode string) *GuideCategoriesListCall {
	c.opt_["regionCode"] = regionCode
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *GuideCategoriesListCall) Fields(s ...googleapi.Field) *GuideCategoriesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *GuideCategoriesListCall) IfNoneMatch(entityTag string) *GuideCategoriesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *GuideCategoriesListCall) Context(ctx context.Context) *GuideCategoriesListCall {
	c.ctx_ = ctx
	return c
}

func (c *GuideCategoriesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["regionCode"]; ok {
		params.Set("regionCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "guideCategories")
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

// Do executes the "youtube.guideCategories.list" call.
// Exactly one of *GuideCategoryListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *GuideCategoryListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *GuideCategoriesListCall) Do() (*GuideCategoryListResponse, error) {
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
	ret := &GuideCategoryListResponse{
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
	//   "description": "Returns a list of categories that can be associated with YouTube channels.",
	//   "httpMethod": "GET",
	//   "id": "youtube.guideCategories.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "hl": {
	//       "default": "en-US",
	//       "description": "The hl parameter specifies the language that will be used for text values in the API response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube channel category ID(s) for the resource(s) that are being retrieved. In a guideCategory resource, the id property specifies the YouTube channel category ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the guideCategory resource properties that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "regionCode": {
	//       "description": "The regionCode parameter instructs the API to return the list of guide categories available in the specified country. The parameter value is an ISO 3166-1 alpha-2 country code.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "guideCategories",
	//   "response": {
	//     "$ref": "GuideCategoryListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.i18nLanguages.list":

type I18nLanguagesListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of application languages that the YouTube
// website supports.
func (r *I18nLanguagesService) List(part string) *I18nLanguagesListCall {
	c := &I18nLanguagesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Hl sets the optional parameter "hl": The hl parameter specifies the
// language that should be used for text values in the API response.
func (c *I18nLanguagesListCall) Hl(hl string) *I18nLanguagesListCall {
	c.opt_["hl"] = hl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *I18nLanguagesListCall) Fields(s ...googleapi.Field) *I18nLanguagesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *I18nLanguagesListCall) IfNoneMatch(entityTag string) *I18nLanguagesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *I18nLanguagesListCall) Context(ctx context.Context) *I18nLanguagesListCall {
	c.ctx_ = ctx
	return c
}

func (c *I18nLanguagesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "i18nLanguages")
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

// Do executes the "youtube.i18nLanguages.list" call.
// Exactly one of *I18nLanguageListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *I18nLanguageListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *I18nLanguagesListCall) Do() (*I18nLanguageListResponse, error) {
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
	ret := &I18nLanguageListResponse{
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
	//   "description": "Returns a list of application languages that the YouTube website supports.",
	//   "httpMethod": "GET",
	//   "id": "youtube.i18nLanguages.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "hl": {
	//       "default": "en_US",
	//       "description": "The hl parameter specifies the language that should be used for text values in the API response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the i18nLanguage resource properties that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "i18nLanguages",
	//   "response": {
	//     "$ref": "I18nLanguageListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.i18nRegions.list":

type I18nRegionsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of content regions that the YouTube website
// supports.
func (r *I18nRegionsService) List(part string) *I18nRegionsListCall {
	c := &I18nRegionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Hl sets the optional parameter "hl": The hl parameter specifies the
// language that should be used for text values in the API response.
func (c *I18nRegionsListCall) Hl(hl string) *I18nRegionsListCall {
	c.opt_["hl"] = hl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *I18nRegionsListCall) Fields(s ...googleapi.Field) *I18nRegionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *I18nRegionsListCall) IfNoneMatch(entityTag string) *I18nRegionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *I18nRegionsListCall) Context(ctx context.Context) *I18nRegionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *I18nRegionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "i18nRegions")
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

// Do executes the "youtube.i18nRegions.list" call.
// Exactly one of *I18nRegionListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *I18nRegionListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *I18nRegionsListCall) Do() (*I18nRegionListResponse, error) {
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
	ret := &I18nRegionListResponse{
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
	//   "description": "Returns a list of content regions that the YouTube website supports.",
	//   "httpMethod": "GET",
	//   "id": "youtube.i18nRegions.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "hl": {
	//       "default": "en_US",
	//       "description": "The hl parameter specifies the language that should be used for text values in the API response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the i18nRegion resource properties that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "i18nRegions",
	//   "response": {
	//     "$ref": "I18nRegionListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.bind":

type LiveBroadcastsBindCall struct {
	s    *Service
	id   string
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Bind: Binds a YouTube broadcast to a stream or removes an existing
// binding between a broadcast and a stream. A broadcast can only be
// bound to one video stream, though a video stream may be bound to more
// than one broadcast.
func (r *LiveBroadcastsService) Bind(id string, part string) *LiveBroadcastsBindCall {
	c := &LiveBroadcastsBindCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	c.part = part
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsBindCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsBindCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsBindCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsBindCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// StreamId sets the optional parameter "streamId": The streamId
// parameter specifies the unique ID of the video stream that is being
// bound to a broadcast. If this parameter is omitted, the API will
// remove any existing binding between the broadcast and a video stream.
func (c *LiveBroadcastsBindCall) StreamId(streamId string) *LiveBroadcastsBindCall {
	c.opt_["streamId"] = streamId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsBindCall) Fields(s ...googleapi.Field) *LiveBroadcastsBindCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsBindCall) Context(ctx context.Context) *LiveBroadcastsBindCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsBindCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["streamId"]; ok {
		params.Set("streamId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts/bind")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.bind" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsBindCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Binds a YouTube broadcast to a stream or removes an existing binding between a broadcast and a stream. A broadcast can only be bound to one video stream, though a video stream may be bound to more than one broadcast.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveBroadcasts.bind",
	//   "parameterOrder": [
	//     "id",
	//     "part"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the unique ID of the broadcast that is being bound to a video stream.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveBroadcast resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "streamId": {
	//       "description": "The streamId parameter specifies the unique ID of the video stream that is being bound to a broadcast. If this parameter is omitted, the API will remove any existing binding between the broadcast and a video stream.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts/bind",
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.bind_direct":

type LiveBroadcastsBindDirectCall struct {
	s    *Service
	id   string
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// BindDirect: Binds a YouTube broadcast to a stream or removes an
// existing binding between a broadcast and a stream. A broadcast can
// only be bound to one video stream, though a video stream may be bound
// to more than one broadcast.
func (r *LiveBroadcastsService) BindDirect(id string, part string) *LiveBroadcastsBindDirectCall {
	c := &LiveBroadcastsBindDirectCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	c.part = part
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsBindDirectCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsBindDirectCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsBindDirectCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsBindDirectCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// StreamId sets the optional parameter "streamId": The streamId
// parameter specifies the unique ID of the video stream that is being
// bound to a broadcast. If this parameter is omitted, the API will
// remove any existing binding between the broadcast and a video stream.
func (c *LiveBroadcastsBindDirectCall) StreamId(streamId string) *LiveBroadcastsBindDirectCall {
	c.opt_["streamId"] = streamId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsBindDirectCall) Fields(s ...googleapi.Field) *LiveBroadcastsBindDirectCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsBindDirectCall) Context(ctx context.Context) *LiveBroadcastsBindDirectCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsBindDirectCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["streamId"]; ok {
		params.Set("streamId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts/bind/direct")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.bind_direct" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsBindDirectCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Binds a YouTube broadcast to a stream or removes an existing binding between a broadcast and a stream. A broadcast can only be bound to one video stream, though a video stream may be bound to more than one broadcast.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveBroadcasts.bind_direct",
	//   "parameterOrder": [
	//     "id",
	//     "part"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the unique ID of the broadcast that is being bound to a video stream.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveBroadcast resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "streamId": {
	//       "description": "The streamId parameter specifies the unique ID of the video stream that is being bound to a broadcast. If this parameter is omitted, the API will remove any existing binding between the broadcast and a video stream.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts/bind/direct",
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.control":

type LiveBroadcastsControlCall struct {
	s    *Service
	id   string
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Control: Controls the settings for a slate that can be displayed in
// the broadcast stream.
func (r *LiveBroadcastsService) Control(id string, part string) *LiveBroadcastsControlCall {
	c := &LiveBroadcastsControlCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	c.part = part
	return c
}

// DisplaySlate sets the optional parameter "displaySlate": The
// displaySlate parameter specifies whether the slate is being enabled
// or disabled.
func (c *LiveBroadcastsControlCall) DisplaySlate(displaySlate bool) *LiveBroadcastsControlCall {
	c.opt_["displaySlate"] = displaySlate
	return c
}

// OffsetTimeMs sets the optional parameter "offsetTimeMs": The
// offsetTimeMs parameter specifies a positive time offset when the
// specified slate change will occur. The value is measured in
// milliseconds from the beginning of the broadcast's monitor stream,
// which is the time that the testing phase for the broadcast began.
// Even though it is specified in milliseconds, the value is actually an
// approximation, and YouTube completes the requested action as closely
// as possible to that time.
//
// If you do not specify a value for this parameter, then YouTube
// performs the action as soon as possible. See the Getting started
// guide for more details.
//
// Important: You should only specify a value for this parameter if your
// broadcast stream is delayed.
func (c *LiveBroadcastsControlCall) OffsetTimeMs(offsetTimeMs uint64) *LiveBroadcastsControlCall {
	c.opt_["offsetTimeMs"] = offsetTimeMs
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsControlCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsControlCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsControlCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsControlCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Walltime sets the optional parameter "walltime": The walltime
// parameter specifies the wall clock time at which the specified slate
// change will occur. The value is specified in ISO 8601
// (YYYY-MM-DDThh:mm:ss.sssZ) format.
func (c *LiveBroadcastsControlCall) Walltime(walltime string) *LiveBroadcastsControlCall {
	c.opt_["walltime"] = walltime
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsControlCall) Fields(s ...googleapi.Field) *LiveBroadcastsControlCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsControlCall) Context(ctx context.Context) *LiveBroadcastsControlCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsControlCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["displaySlate"]; ok {
		params.Set("displaySlate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["offsetTimeMs"]; ok {
		params.Set("offsetTimeMs", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["walltime"]; ok {
		params.Set("walltime", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts/control")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.control" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsControlCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Controls the settings for a slate that can be displayed in the broadcast stream.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveBroadcasts.control",
	//   "parameterOrder": [
	//     "id",
	//     "part"
	//   ],
	//   "parameters": {
	//     "displaySlate": {
	//       "description": "The displaySlate parameter specifies whether the slate is being enabled or disabled.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies the YouTube live broadcast ID that uniquely identifies the broadcast in which the slate is being updated.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "offsetTimeMs": {
	//       "description": "The offsetTimeMs parameter specifies a positive time offset when the specified slate change will occur. The value is measured in milliseconds from the beginning of the broadcast's monitor stream, which is the time that the testing phase for the broadcast began. Even though it is specified in milliseconds, the value is actually an approximation, and YouTube completes the requested action as closely as possible to that time.\n\nIf you do not specify a value for this parameter, then YouTube performs the action as soon as possible. See the Getting started guide for more details.\n\nImportant: You should only specify a value for this parameter if your broadcast stream is delayed.",
	//       "format": "uint64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveBroadcast resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "walltime": {
	//       "description": "The walltime parameter specifies the wall clock time at which the specified slate change will occur. The value is specified in ISO 8601 (YYYY-MM-DDThh:mm:ss.sssZ) format.",
	//       "format": "date-time",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts/control",
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.delete":

type LiveBroadcastsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a broadcast.
func (r *LiveBroadcastsService) Delete(id string) *LiveBroadcastsDeleteCall {
	c := &LiveBroadcastsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsDeleteCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsDeleteCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsDeleteCall) Fields(s ...googleapi.Field) *LiveBroadcastsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsDeleteCall) Context(ctx context.Context) *LiveBroadcastsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.delete" call.
func (c *LiveBroadcastsDeleteCall) Do() error {
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
	//   "description": "Deletes a broadcast.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.liveBroadcasts.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube live broadcast ID for the resource that is being deleted.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.insert":

type LiveBroadcastsInsertCall struct {
	s             *Service
	part          string
	livebroadcast *LiveBroadcast
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Creates a broadcast.
func (r *LiveBroadcastsService) Insert(part string, livebroadcast *LiveBroadcast) *LiveBroadcastsInsertCall {
	c := &LiveBroadcastsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.livebroadcast = livebroadcast
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsInsertCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsInsertCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsInsertCall) Fields(s ...googleapi.Field) *LiveBroadcastsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsInsertCall) Context(ctx context.Context) *LiveBroadcastsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.livebroadcast)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts")
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

// Do executes the "youtube.liveBroadcasts.insert" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsInsertCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Creates a broadcast.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveBroadcasts.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part properties that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts",
	//   "request": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.list":

type LiveBroadcastsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of YouTube broadcasts that match the API request
// parameters.
func (r *LiveBroadcastsService) List(part string) *LiveBroadcastsListCall {
	c := &LiveBroadcastsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// BroadcastStatus sets the optional parameter "broadcastStatus": The
// broadcastStatus parameter filters the API response to only include
// broadcasts with the specified status.
//
// Possible values:
//   "active" - Return current live broadcasts.
//   "all" - Return all broadcasts.
//   "completed" - Return broadcasts that have already ended.
//   "upcoming" - Return broadcasts that have not yet started.
func (c *LiveBroadcastsListCall) BroadcastStatus(broadcastStatus string) *LiveBroadcastsListCall {
	c.opt_["broadcastStatus"] = broadcastStatus
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of YouTube broadcast IDs that identify the
// broadcasts being retrieved. In a liveBroadcast resource, the id
// property specifies the broadcast's ID.
func (c *LiveBroadcastsListCall) Id(id string) *LiveBroadcastsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *LiveBroadcastsListCall) MaxResults(maxResults int64) *LiveBroadcastsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": The mine parameter can be
// used to instruct the API to only return broadcasts owned by the
// authenticated user. Set the parameter value to true to only retrieve
// your own broadcasts.
func (c *LiveBroadcastsListCall) Mine(mine bool) *LiveBroadcastsListCall {
	c.opt_["mine"] = mine
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsListCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsListCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *LiveBroadcastsListCall) PageToken(pageToken string) *LiveBroadcastsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsListCall) Fields(s ...googleapi.Field) *LiveBroadcastsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LiveBroadcastsListCall) IfNoneMatch(entityTag string) *LiveBroadcastsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsListCall) Context(ctx context.Context) *LiveBroadcastsListCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["broadcastStatus"]; ok {
		params.Set("broadcastStatus", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts")
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

// Do executes the "youtube.liveBroadcasts.list" call.
// Exactly one of *LiveBroadcastListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *LiveBroadcastListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsListCall) Do() (*LiveBroadcastListResponse, error) {
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
	ret := &LiveBroadcastListResponse{
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
	//   "description": "Returns a list of YouTube broadcasts that match the API request parameters.",
	//   "httpMethod": "GET",
	//   "id": "youtube.liveBroadcasts.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "broadcastStatus": {
	//       "description": "The broadcastStatus parameter filters the API response to only include broadcasts with the specified status.",
	//       "enum": [
	//         "active",
	//         "all",
	//         "completed",
	//         "upcoming"
	//       ],
	//       "enumDescriptions": [
	//         "Return current live broadcasts.",
	//         "Return all broadcasts.",
	//         "Return broadcasts that have already ended.",
	//         "Return broadcasts that have not yet started."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of YouTube broadcast IDs that identify the broadcasts being retrieved. In a liveBroadcast resource, the id property specifies the broadcast's ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "The mine parameter can be used to instruct the API to only return broadcasts owned by the authenticated user. Set the parameter value to true to only retrieve your own broadcasts.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveBroadcast resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts",
	//   "response": {
	//     "$ref": "LiveBroadcastListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.transition":

type LiveBroadcastsTransitionCall struct {
	s               *Service
	broadcastStatus string
	id              string
	part            string
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Transition: Changes the status of a YouTube live broadcast and
// initiates any processes associated with the new status. For example,
// when you transition a broadcast's status to testing, YouTube starts
// to transmit video to that broadcast's monitor stream. Before calling
// this method, you should confirm that the value of the
// status.streamStatus property for the stream bound to your broadcast
// is active.
func (r *LiveBroadcastsService) Transition(broadcastStatus string, id string, part string) *LiveBroadcastsTransitionCall {
	c := &LiveBroadcastsTransitionCall{s: r.s, opt_: make(map[string]interface{})}
	c.broadcastStatus = broadcastStatus
	c.id = id
	c.part = part
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsTransitionCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsTransitionCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsTransitionCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsTransitionCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsTransitionCall) Fields(s ...googleapi.Field) *LiveBroadcastsTransitionCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsTransitionCall) Context(ctx context.Context) *LiveBroadcastsTransitionCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsTransitionCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("broadcastStatus", fmt.Sprintf("%v", c.broadcastStatus))
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts/transition")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.transition" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsTransitionCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Changes the status of a YouTube live broadcast and initiates any processes associated with the new status. For example, when you transition a broadcast's status to testing, YouTube starts to transmit video to that broadcast's monitor stream. Before calling this method, you should confirm that the value of the status.streamStatus property for the stream bound to your broadcast is active.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveBroadcasts.transition",
	//   "parameterOrder": [
	//     "broadcastStatus",
	//     "id",
	//     "part"
	//   ],
	//   "parameters": {
	//     "broadcastStatus": {
	//       "description": "The broadcastStatus parameter identifies the state to which the broadcast is changing. Note that to transition a broadcast to either the testing or live state, the status.streamStatus must be active for the stream that the broadcast is bound to.",
	//       "enum": [
	//         "complete",
	//         "live",
	//         "testing"
	//       ],
	//       "enumDescriptions": [
	//         "The broadcast is over. YouTube stops transmitting video.",
	//         "The broadcast is visible to its audience. YouTube transmits video to the broadcast's monitor stream and its broadcast stream.",
	//         "Start testing the broadcast. YouTube transmits video to the broadcast's monitor stream. Note that you can only transition a broadcast to the testing state if its contentDetails.monitorStream.enableMonitorStream property is set to true."
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies the unique ID of the broadcast that is transitioning to another status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveBroadcast resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, contentDetails, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts/transition",
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveBroadcasts.update":

type LiveBroadcastsUpdateCall struct {
	s             *Service
	part          string
	livebroadcast *LiveBroadcast
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Updates a broadcast. For example, you could modify the
// broadcast settings defined in the liveBroadcast resource's
// contentDetails object.
func (r *LiveBroadcastsService) Update(part string, livebroadcast *LiveBroadcast) *LiveBroadcastsUpdateCall {
	c := &LiveBroadcastsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.livebroadcast = livebroadcast
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveBroadcastsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveBroadcastsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveBroadcastsUpdateCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveBroadcastsUpdateCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveBroadcastsUpdateCall) Fields(s ...googleapi.Field) *LiveBroadcastsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveBroadcastsUpdateCall) Context(ctx context.Context) *LiveBroadcastsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveBroadcastsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.livebroadcast)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveBroadcasts")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveBroadcasts.update" call.
// Exactly one of *LiveBroadcast or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveBroadcast.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveBroadcastsUpdateCall) Do() (*LiveBroadcast, error) {
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
	ret := &LiveBroadcast{
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
	//   "description": "Updates a broadcast. For example, you could modify the broadcast settings defined in the liveBroadcast resource's contentDetails object.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.liveBroadcasts.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part properties that you can include in the parameter value are id, snippet, contentDetails, and status.\n\nNote that this method will override the existing values for all of the mutable properties that are contained in any parts that the parameter value specifies. For example, a broadcast's privacy status is defined in the status part. As such, if your request is updating a private or unlisted broadcast, and the request's part parameter value includes the status part, the broadcast's privacy setting will be updated to whatever value the request body specifies. If the request body does not specify a value, the existing privacy setting will be removed and the broadcast will revert to the default privacy setting.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveBroadcasts",
	//   "request": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "response": {
	//     "$ref": "LiveBroadcast"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveStreams.delete":

type LiveStreamsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a video stream.
func (r *LiveStreamsService) Delete(id string) *LiveStreamsDeleteCall {
	c := &LiveStreamsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveStreamsDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveStreamsDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveStreamsDeleteCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveStreamsDeleteCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveStreamsDeleteCall) Fields(s ...googleapi.Field) *LiveStreamsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveStreamsDeleteCall) Context(ctx context.Context) *LiveStreamsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveStreamsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveStreams")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveStreams.delete" call.
func (c *LiveStreamsDeleteCall) Do() error {
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
	//   "description": "Deletes a video stream.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.liveStreams.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube live stream ID for the resource that is being deleted.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveStreams",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveStreams.insert":

type LiveStreamsInsertCall struct {
	s          *Service
	part       string
	livestream *LiveStream
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Insert: Creates a video stream. The stream enables you to send your
// video to YouTube, which can then broadcast the video to your
// audience.
func (r *LiveStreamsService) Insert(part string, livestream *LiveStream) *LiveStreamsInsertCall {
	c := &LiveStreamsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.livestream = livestream
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveStreamsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveStreamsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveStreamsInsertCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveStreamsInsertCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveStreamsInsertCall) Fields(s ...googleapi.Field) *LiveStreamsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveStreamsInsertCall) Context(ctx context.Context) *LiveStreamsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveStreamsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.livestream)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveStreams")
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

// Do executes the "youtube.liveStreams.insert" call.
// Exactly one of *LiveStream or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveStream.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *LiveStreamsInsertCall) Do() (*LiveStream, error) {
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
	ret := &LiveStream{
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
	//   "description": "Creates a video stream. The stream enables you to send your video to YouTube, which can then broadcast the video to your audience.",
	//   "httpMethod": "POST",
	//   "id": "youtube.liveStreams.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part properties that you can include in the parameter value are id, snippet, cdn, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveStreams",
	//   "request": {
	//     "$ref": "LiveStream"
	//   },
	//   "response": {
	//     "$ref": "LiveStream"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.liveStreams.list":

type LiveStreamsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of video streams that match the API request
// parameters.
func (r *LiveStreamsService) List(part string) *LiveStreamsListCall {
	c := &LiveStreamsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of YouTube stream IDs that identify the streams
// being retrieved. In a liveStream resource, the id property specifies
// the stream's ID.
func (c *LiveStreamsListCall) Id(id string) *LiveStreamsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *LiveStreamsListCall) MaxResults(maxResults int64) *LiveStreamsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": The mine parameter can be
// used to instruct the API to only return streams owned by the
// authenticated user. Set the parameter value to true to only retrieve
// your own streams.
func (c *LiveStreamsListCall) Mine(mine bool) *LiveStreamsListCall {
	c.opt_["mine"] = mine
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveStreamsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveStreamsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveStreamsListCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveStreamsListCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *LiveStreamsListCall) PageToken(pageToken string) *LiveStreamsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveStreamsListCall) Fields(s ...googleapi.Field) *LiveStreamsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LiveStreamsListCall) IfNoneMatch(entityTag string) *LiveStreamsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveStreamsListCall) Context(ctx context.Context) *LiveStreamsListCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveStreamsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveStreams")
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

// Do executes the "youtube.liveStreams.list" call.
// Exactly one of *LiveStreamListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *LiveStreamListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LiveStreamsListCall) Do() (*LiveStreamListResponse, error) {
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
	ret := &LiveStreamListResponse{
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
	//   "description": "Returns a list of video streams that match the API request parameters.",
	//   "httpMethod": "GET",
	//   "id": "youtube.liveStreams.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of YouTube stream IDs that identify the streams being retrieved. In a liveStream resource, the id property specifies the stream's ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "The mine parameter can be used to instruct the API to only return streams owned by the authenticated user. Set the parameter value to true to only retrieve your own streams.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more liveStream resource properties that the API response will include. The part names that you can include in the parameter value are id, snippet, cdn, and status.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveStreams",
	//   "response": {
	//     "$ref": "LiveStreamListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly"
	//   ]
	// }

}

// method id "youtube.liveStreams.update":

type LiveStreamsUpdateCall struct {
	s          *Service
	part       string
	livestream *LiveStream
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Update: Updates a video stream. If the properties that you want to
// change cannot be updated, then you need to create a new stream with
// the proper settings.
func (r *LiveStreamsService) Update(part string, livestream *LiveStream) *LiveStreamsUpdateCall {
	c := &LiveStreamsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.livestream = livestream
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *LiveStreamsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *LiveStreamsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *LiveStreamsUpdateCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *LiveStreamsUpdateCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LiveStreamsUpdateCall) Fields(s ...googleapi.Field) *LiveStreamsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LiveStreamsUpdateCall) Context(ctx context.Context) *LiveStreamsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *LiveStreamsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.livestream)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "liveStreams")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.liveStreams.update" call.
// Exactly one of *LiveStream or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *LiveStream.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *LiveStreamsUpdateCall) Do() (*LiveStream, error) {
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
	ret := &LiveStream{
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
	//   "description": "Updates a video stream. If the properties that you want to change cannot be updated, then you need to create a new stream with the proper settings.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.liveStreams.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nThe part properties that you can include in the parameter value are id, snippet, cdn, and status.\n\nNote that this method will override the existing values for all of the mutable properties that are contained in any parts that the parameter value specifies. If the request body does not specify a value for a mutable property, the existing value for that property will be removed.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "liveStreams",
	//   "request": {
	//     "$ref": "LiveStream"
	//   },
	//   "response": {
	//     "$ref": "LiveStream"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl"
	//   ]
	// }

}

// method id "youtube.playlistItems.delete":

type PlaylistItemsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a playlist item.
func (r *PlaylistItemsService) Delete(id string) *PlaylistItemsDeleteCall {
	c := &PlaylistItemsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistItemsDeleteCall) Fields(s ...googleapi.Field) *PlaylistItemsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistItemsDeleteCall) Context(ctx context.Context) *PlaylistItemsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistItemsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlistItems")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.playlistItems.delete" call.
func (c *PlaylistItemsDeleteCall) Do() error {
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
	//   "description": "Deletes a playlist item.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.playlistItems.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube playlist item ID for the playlist item that is being deleted. In a playlistItem resource, the id property specifies the playlist item's ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlistItems",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlistItems.insert":

type PlaylistItemsInsertCall struct {
	s            *Service
	part         string
	playlistitem *PlaylistItem
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Insert: Adds a resource to a playlist.
func (r *PlaylistItemsService) Insert(part string, playlistitem *PlaylistItem) *PlaylistItemsInsertCall {
	c := &PlaylistItemsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.playlistitem = playlistitem
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistItemsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistItemsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistItemsInsertCall) Fields(s ...googleapi.Field) *PlaylistItemsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistItemsInsertCall) Context(ctx context.Context) *PlaylistItemsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistItemsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.playlistitem)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlistItems")
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

// Do executes the "youtube.playlistItems.insert" call.
// Exactly one of *PlaylistItem or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PlaylistItem.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PlaylistItemsInsertCall) Do() (*PlaylistItem, error) {
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
	ret := &PlaylistItem{
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
	//   "description": "Adds a resource to a playlist.",
	//   "httpMethod": "POST",
	//   "id": "youtube.playlistItems.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlistItems",
	//   "request": {
	//     "$ref": "PlaylistItem"
	//   },
	//   "response": {
	//     "$ref": "PlaylistItem"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlistItems.list":

type PlaylistItemsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a collection of playlist items that match the API
// request parameters. You can retrieve all of the playlist items in a
// specified playlist or retrieve one or more playlist items by their
// unique IDs.
func (r *PlaylistItemsService) List(part string) *PlaylistItemsListCall {
	c := &PlaylistItemsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of one or more unique playlist item IDs.
func (c *PlaylistItemsListCall) Id(id string) *PlaylistItemsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *PlaylistItemsListCall) MaxResults(maxResults int64) *PlaylistItemsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistItemsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistItemsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *PlaylistItemsListCall) PageToken(pageToken string) *PlaylistItemsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PlaylistId sets the optional parameter "playlistId": The playlistId
// parameter specifies the unique ID of the playlist for which you want
// to retrieve playlist items. Note that even though this is an optional
// parameter, every request to retrieve playlist items must specify a
// value for either the id parameter or the playlistId parameter.
func (c *PlaylistItemsListCall) PlaylistId(playlistId string) *PlaylistItemsListCall {
	c.opt_["playlistId"] = playlistId
	return c
}

// VideoId sets the optional parameter "videoId": The videoId parameter
// specifies that the request should return only the playlist items that
// contain the specified video.
func (c *PlaylistItemsListCall) VideoId(videoId string) *PlaylistItemsListCall {
	c.opt_["videoId"] = videoId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistItemsListCall) Fields(s ...googleapi.Field) *PlaylistItemsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PlaylistItemsListCall) IfNoneMatch(entityTag string) *PlaylistItemsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistItemsListCall) Context(ctx context.Context) *PlaylistItemsListCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistItemsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["playlistId"]; ok {
		params.Set("playlistId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoId"]; ok {
		params.Set("videoId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlistItems")
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

// Do executes the "youtube.playlistItems.list" call.
// Exactly one of *PlaylistItemListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *PlaylistItemListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PlaylistItemsListCall) Do() (*PlaylistItemListResponse, error) {
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
	ret := &PlaylistItemListResponse{
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
	//   "description": "Returns a collection of playlist items that match the API request parameters. You can retrieve all of the playlist items in a specified playlist or retrieve one or more playlist items by their unique IDs.",
	//   "httpMethod": "GET",
	//   "id": "youtube.playlistItems.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of one or more unique playlist item IDs.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more playlistItem resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a playlistItem resource, the snippet property contains numerous fields, including the title, description, position, and resourceId properties. As such, if you set part=snippet, the API response will contain all of those properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "playlistId": {
	//       "description": "The playlistId parameter specifies the unique ID of the playlist for which you want to retrieve playlist items. Note that even though this is an optional parameter, every request to retrieve playlist items must specify a value for either the id parameter or the playlistId parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "The videoId parameter specifies that the request should return only the playlist items that contain the specified video.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlistItems",
	//   "response": {
	//     "$ref": "PlaylistItemListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsSubscription": true
	// }

}

// method id "youtube.playlistItems.update":

type PlaylistItemsUpdateCall struct {
	s            *Service
	part         string
	playlistitem *PlaylistItem
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Update: Modifies a playlist item. For example, you could update the
// item's position in the playlist.
func (r *PlaylistItemsService) Update(part string, playlistitem *PlaylistItem) *PlaylistItemsUpdateCall {
	c := &PlaylistItemsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.playlistitem = playlistitem
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistItemsUpdateCall) Fields(s ...googleapi.Field) *PlaylistItemsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistItemsUpdateCall) Context(ctx context.Context) *PlaylistItemsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistItemsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.playlistitem)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlistItems")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.playlistItems.update" call.
// Exactly one of *PlaylistItem or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PlaylistItem.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PlaylistItemsUpdateCall) Do() (*PlaylistItem, error) {
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
	ret := &PlaylistItem{
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
	//   "description": "Modifies a playlist item. For example, you could update the item's position in the playlist.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.playlistItems.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nNote that this method will override the existing values for all of the mutable properties that are contained in any parts that the parameter value specifies. For example, a playlist item can specify a start time and end time, which identify the times portion of the video that should play when users watch the video in the playlist. If your request is updating a playlist item that sets these values, and the request's part parameter value includes the contentDetails part, the playlist item's start and end times will be updated to whatever value the request body specifies. If the request body does not specify values, the existing start and end times will be removed and replaced with the default settings.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlistItems",
	//   "request": {
	//     "$ref": "PlaylistItem"
	//   },
	//   "response": {
	//     "$ref": "PlaylistItem"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlists.delete":

type PlaylistsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a playlist.
func (r *PlaylistsService) Delete(id string) *PlaylistsDeleteCall {
	c := &PlaylistsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistsDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistsDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistsDeleteCall) Fields(s ...googleapi.Field) *PlaylistsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistsDeleteCall) Context(ctx context.Context) *PlaylistsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlists")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.playlists.delete" call.
func (c *PlaylistsDeleteCall) Do() error {
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
	//   "description": "Deletes a playlist.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.playlists.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube playlist ID for the playlist that is being deleted. In a playlist resource, the id property specifies the playlist's ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlists",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlists.insert":

type PlaylistsInsertCall struct {
	s        *Service
	part     string
	playlist *Playlist
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Insert: Creates a playlist.
func (r *PlaylistsService) Insert(part string, playlist *Playlist) *PlaylistsInsertCall {
	c := &PlaylistsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.playlist = playlist
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistsInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistsInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *PlaylistsInsertCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *PlaylistsInsertCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistsInsertCall) Fields(s ...googleapi.Field) *PlaylistsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistsInsertCall) Context(ctx context.Context) *PlaylistsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.playlist)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlists")
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

// Do executes the "youtube.playlists.insert" call.
// Exactly one of *Playlist or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Playlist.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PlaylistsInsertCall) Do() (*Playlist, error) {
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
	ret := &Playlist{
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
	//   "description": "Creates a playlist.",
	//   "httpMethod": "POST",
	//   "id": "youtube.playlists.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlists",
	//   "request": {
	//     "$ref": "Playlist"
	//   },
	//   "response": {
	//     "$ref": "Playlist"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlists.list":

type PlaylistsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a collection of playlists that match the API request
// parameters. For example, you can retrieve all playlists that the
// authenticated user owns, or you can retrieve one or more playlists by
// their unique IDs.
func (r *PlaylistsService) List(part string) *PlaylistsListCall {
	c := &PlaylistsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// ChannelId sets the optional parameter "channelId": This value
// indicates that the API should only return the specified channel's
// playlists.
func (c *PlaylistsListCall) ChannelId(channelId string) *PlaylistsListCall {
	c.opt_["channelId"] = channelId
	return c
}

// Hl sets the optional parameter "hl": The hl parameter should be used
// for filter out the properties that are not in the given language.
// Used for the snippet part.
func (c *PlaylistsListCall) Hl(hl string) *PlaylistsListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube playlist ID(s) for the
// resource(s) that are being retrieved. In a playlist resource, the id
// property specifies the playlist's YouTube playlist ID.
func (c *PlaylistsListCall) Id(id string) *PlaylistsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *PlaylistsListCall) MaxResults(maxResults int64) *PlaylistsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": Set this parameter's value
// to true to instruct the API to only return playlists owned by the
// authenticated user.
func (c *PlaylistsListCall) Mine(mine bool) *PlaylistsListCall {
	c.opt_["mine"] = mine
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *PlaylistsListCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *PlaylistsListCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *PlaylistsListCall) PageToken(pageToken string) *PlaylistsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistsListCall) Fields(s ...googleapi.Field) *PlaylistsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PlaylistsListCall) IfNoneMatch(entityTag string) *PlaylistsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistsListCall) Context(ctx context.Context) *PlaylistsListCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlists")
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

// Do executes the "youtube.playlists.list" call.
// Exactly one of *PlaylistListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *PlaylistListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PlaylistsListCall) Do() (*PlaylistListResponse, error) {
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
	ret := &PlaylistListResponse{
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
	//   "description": "Returns a collection of playlists that match the API request parameters. For example, you can retrieve all playlists that the authenticated user owns, or you can retrieve one or more playlists by their unique IDs.",
	//   "httpMethod": "GET",
	//   "id": "youtube.playlists.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "This value indicates that the API should only return the specified channel's playlists.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "hl": {
	//       "description": "The hl parameter should be used for filter out the properties that are not in the given language. Used for the snippet part.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube playlist ID(s) for the resource(s) that are being retrieved. In a playlist resource, the id property specifies the playlist's YouTube playlist ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "Set this parameter's value to true to instruct the API to only return playlists owned by the authenticated user.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more playlist resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a playlist resource, the snippet property contains properties like author, title, description, tags, and timeCreated. As such, if you set part=snippet, the API response will contain all of those properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlists",
	//   "response": {
	//     "$ref": "PlaylistListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.playlists.update":

type PlaylistsUpdateCall struct {
	s        *Service
	part     string
	playlist *Playlist
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Update: Modifies a playlist. For example, you could change a
// playlist's title, description, or privacy status.
func (r *PlaylistsService) Update(part string, playlist *Playlist) *PlaylistsUpdateCall {
	c := &PlaylistsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.playlist = playlist
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *PlaylistsUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *PlaylistsUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlaylistsUpdateCall) Fields(s ...googleapi.Field) *PlaylistsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlaylistsUpdateCall) Context(ctx context.Context) *PlaylistsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *PlaylistsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.playlist)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "playlists")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.playlists.update" call.
// Exactly one of *Playlist or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Playlist.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PlaylistsUpdateCall) Do() (*Playlist, error) {
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
	ret := &Playlist{
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
	//   "description": "Modifies a playlist. For example, you could change a playlist's title, description, or privacy status.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.playlists.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nNote that this method will override the existing values for mutable properties that are contained in any parts that the request body specifies. For example, a playlist's description is contained in the snippet part, which must be included in the request body. If the request does not specify a value for the snippet.description property, the playlist's existing description will be deleted.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "playlists",
	//   "request": {
	//     "$ref": "Playlist"
	//   },
	//   "response": {
	//     "$ref": "Playlist"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.search.list":

type SearchListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a collection of search results that match the query
// parameters specified in the API request. By default, a search result
// set identifies matching video, channel, and playlist resources, but
// you can also configure queries to only retrieve a specific type of
// resource.
func (r *SearchService) List(part string) *SearchListCall {
	c := &SearchListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// ChannelId sets the optional parameter "channelId": The channelId
// parameter indicates that the API response should only contain
// resources created by the channel
func (c *SearchListCall) ChannelId(channelId string) *SearchListCall {
	c.opt_["channelId"] = channelId
	return c
}

// ChannelType sets the optional parameter "channelType": The
// channelType parameter lets you restrict a search to a particular type
// of channel.
//
// Possible values:
//   "any" - Return all channels.
//   "show" - Only retrieve shows.
func (c *SearchListCall) ChannelType(channelType string) *SearchListCall {
	c.opt_["channelType"] = channelType
	return c
}

// EventType sets the optional parameter "eventType": The eventType
// parameter restricts a search to broadcast events. If you specify a
// value for this parameter, you must also set the type parameter's
// value to video.
//
// Possible values:
//   "completed" - Only include completed broadcasts.
//   "live" - Only include active broadcasts.
//   "upcoming" - Only include upcoming broadcasts.
func (c *SearchListCall) EventType(eventType string) *SearchListCall {
	c.opt_["eventType"] = eventType
	return c
}

// ForContentOwner sets the optional parameter "forContentOwner": Note:
// This parameter is intended exclusively for YouTube content
// partners.
//
// The forContentOwner parameter restricts the search to only retrieve
// resources owned by the content owner specified by the
// onBehalfOfContentOwner parameter. The user must be authenticated
// using a CMS account linked to the specified content owner and
// onBehalfOfContentOwner must be provided.
func (c *SearchListCall) ForContentOwner(forContentOwner bool) *SearchListCall {
	c.opt_["forContentOwner"] = forContentOwner
	return c
}

// ForDeveloper sets the optional parameter "forDeveloper": The
// forDeveloper parameter restricts the search to only retrieve videos
// uploaded via the developer's application or website. The API server
// uses the request's authorization credentials to identify the
// developer. Therefore, a developer can restrict results to videos
// uploaded through the developer's own app or website but not to videos
// uploaded through other apps or sites.
func (c *SearchListCall) ForDeveloper(forDeveloper bool) *SearchListCall {
	c.opt_["forDeveloper"] = forDeveloper
	return c
}

// ForMine sets the optional parameter "forMine": The forMine parameter
// restricts the search to only retrieve videos owned by the
// authenticated user. If you set this parameter to true, then the type
// parameter's value must also be set to video.
func (c *SearchListCall) ForMine(forMine bool) *SearchListCall {
	c.opt_["forMine"] = forMine
	return c
}

// Location sets the optional parameter "location": The location
// parameter, in conjunction with the locationRadius parameter, defines
// a circular geographic area and also restricts a search to videos that
// specify, in their metadata, a geographic location that falls within
// that area. The parameter value is a string that specifies
// latitude/longitude coordinates e.g. (37.42307,-122.08427).
//
//
// - The location parameter value identifies the point at the center of
// the area.
// - The locationRadius parameter specifies the maximum distance that
// the location associated with a video can be from that point for the
// video to still be included in the search results.The API returns an
// error if your request specifies a value for the location parameter
// but does not also specify a value for the locationRadius parameter.
func (c *SearchListCall) Location(location string) *SearchListCall {
	c.opt_["location"] = location
	return c
}

// LocationRadius sets the optional parameter "locationRadius": The
// locationRadius parameter, in conjunction with the location parameter,
// defines a circular geographic area.
//
// The parameter value must be a floating point number followed by a
// measurement unit. Valid measurement units are m, km, ft, and mi. For
// example, valid parameter values include 1500m, 5km, 10000ft, and
// 0.75mi. The API does not support locationRadius parameter values
// larger than 1000 kilometers.
//
// Note: See the definition of the location parameter for more
// information.
func (c *SearchListCall) LocationRadius(locationRadius string) *SearchListCall {
	c.opt_["locationRadius"] = locationRadius
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *SearchListCall) MaxResults(maxResults int64) *SearchListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *SearchListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *SearchListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Order sets the optional parameter "order": The order parameter
// specifies the method that will be used to order resources in the API
// response.
//
// Possible values:
//   "date" - Resources are sorted in reverse chronological order based
// on the date they were created.
//   "rating" - Resources are sorted from highest to lowest rating.
//   "relevance" - Resources are sorted based on their relevance to the
// search query. This is the default value for this parameter.
//   "title" - Resources are sorted alphabetically by title.
//   "videoCount" - Channels are sorted in descending order of their
// number of uploaded videos.
//   "viewCount" - Resources are sorted from highest to lowest number of
// views.
func (c *SearchListCall) Order(order string) *SearchListCall {
	c.opt_["order"] = order
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *SearchListCall) PageToken(pageToken string) *SearchListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PublishedAfter sets the optional parameter "publishedAfter": The
// publishedAfter parameter indicates that the API response should only
// contain resources created after the specified time. The value is an
// RFC 3339 formatted date-time value (1970-01-01T00:00:00Z).
func (c *SearchListCall) PublishedAfter(publishedAfter string) *SearchListCall {
	c.opt_["publishedAfter"] = publishedAfter
	return c
}

// PublishedBefore sets the optional parameter "publishedBefore": The
// publishedBefore parameter indicates that the API response should only
// contain resources created before the specified time. The value is an
// RFC 3339 formatted date-time value (1970-01-01T00:00:00Z).
func (c *SearchListCall) PublishedBefore(publishedBefore string) *SearchListCall {
	c.opt_["publishedBefore"] = publishedBefore
	return c
}

// Q sets the optional parameter "q": The q parameter specifies the
// query term to search for.
//
// Your request can also use the Boolean NOT (-) and OR (|) operators to
// exclude videos or to find videos that are associated with one of
// several search terms. For example, to search for videos matching
// either "boating" or "sailing", set the q parameter value to
// boating|sailing. Similarly, to search for videos matching either
// "boating" or "sailing" but not "fishing", set the q parameter value
// to boating|sailing -fishing. Note that the pipe character must be
// URL-escaped when it is sent in your API request. The URL-escaped
// value for the pipe character is %7C.
func (c *SearchListCall) Q(q string) *SearchListCall {
	c.opt_["q"] = q
	return c
}

// RegionCode sets the optional parameter "regionCode": The regionCode
// parameter instructs the API to return search results for the
// specified country. The parameter value is an ISO 3166-1 alpha-2
// country code.
func (c *SearchListCall) RegionCode(regionCode string) *SearchListCall {
	c.opt_["regionCode"] = regionCode
	return c
}

// RelatedToVideoId sets the optional parameter "relatedToVideoId": The
// relatedToVideoId parameter retrieves a list of videos that are
// related to the video that the parameter value identifies. The
// parameter value must be set to a YouTube video ID and, if you are
// using this parameter, the type parameter must be set to video.
func (c *SearchListCall) RelatedToVideoId(relatedToVideoId string) *SearchListCall {
	c.opt_["relatedToVideoId"] = relatedToVideoId
	return c
}

// RelevanceLanguage sets the optional parameter "relevanceLanguage":
// The relevanceLanguage parameter instructs the API to return search
// results that are most relevant to the specified language. The
// parameter value is typically an ISO 639-1 two-letter language code.
// However, you should use the values zh-Hans for simplified Chinese and
// zh-Hant for traditional Chinese. Please note that results in other
// languages will still be returned if they are highly relevant to the
// search query term.
func (c *SearchListCall) RelevanceLanguage(relevanceLanguage string) *SearchListCall {
	c.opt_["relevanceLanguage"] = relevanceLanguage
	return c
}

// SafeSearch sets the optional parameter "safeSearch": The safeSearch
// parameter indicates whether the search results should include
// restricted content as well as standard content.
//
// Possible values:
//   "moderate" - YouTube will filter some content from search results
// and, at the least, will filter content that is restricted in your
// locale. Based on their content, search results could be removed from
// search results or demoted in search results. This is the default
// parameter value.
//   "none" - YouTube will not filter the search result set.
//   "strict" - YouTube will try to exclude all restricted content from
// the search result set. Based on their content, search results could
// be removed from search results or demoted in search results.
func (c *SearchListCall) SafeSearch(safeSearch string) *SearchListCall {
	c.opt_["safeSearch"] = safeSearch
	return c
}

// TopicId sets the optional parameter "topicId": The topicId parameter
// indicates that the API response should only contain resources
// associated with the specified topic. The value identifies a Freebase
// topic ID.
func (c *SearchListCall) TopicId(topicId string) *SearchListCall {
	c.opt_["topicId"] = topicId
	return c
}

// Type sets the optional parameter "type": The type parameter restricts
// a search query to only retrieve a particular type of resource. The
// value is a comma-separated list of resource types.
func (c *SearchListCall) Type(type_ string) *SearchListCall {
	c.opt_["type"] = type_
	return c
}

// VideoCaption sets the optional parameter "videoCaption": The
// videoCaption parameter indicates whether the API should filter video
// search results based on whether they have captions. If you specify a
// value for this parameter, you must also set the type parameter's
// value to video.
//
// Possible values:
//   "any" - Do not filter results based on caption availability.
//   "closedCaption" - Only include videos that have captions.
//   "none" - Only include videos that do not have captions.
func (c *SearchListCall) VideoCaption(videoCaption string) *SearchListCall {
	c.opt_["videoCaption"] = videoCaption
	return c
}

// VideoCategoryId sets the optional parameter "videoCategoryId": The
// videoCategoryId parameter filters video search results based on their
// category. If you specify a value for this parameter, you must also
// set the type parameter's value to video.
func (c *SearchListCall) VideoCategoryId(videoCategoryId string) *SearchListCall {
	c.opt_["videoCategoryId"] = videoCategoryId
	return c
}

// VideoDefinition sets the optional parameter "videoDefinition": The
// videoDefinition parameter lets you restrict a search to only include
// either high definition (HD) or standard definition (SD) videos. HD
// videos are available for playback in at least 720p, though higher
// resolutions, like 1080p, might also be available. If you specify a
// value for this parameter, you must also set the type parameter's
// value to video.
//
// Possible values:
//   "any" - Return all videos, regardless of their resolution.
//   "high" - Only retrieve HD videos.
//   "standard" - Only retrieve videos in standard definition.
func (c *SearchListCall) VideoDefinition(videoDefinition string) *SearchListCall {
	c.opt_["videoDefinition"] = videoDefinition
	return c
}

// VideoDimension sets the optional parameter "videoDimension": The
// videoDimension parameter lets you restrict a search to only retrieve
// 2D or 3D videos. If you specify a value for this parameter, you must
// also set the type parameter's value to video.
//
// Possible values:
//   "2d" - Restrict search results to exclude 3D videos.
//   "3d" - Restrict search results to only include 3D videos.
//   "any" - Include both 3D and non-3D videos in returned results. This
// is the default value.
func (c *SearchListCall) VideoDimension(videoDimension string) *SearchListCall {
	c.opt_["videoDimension"] = videoDimension
	return c
}

// VideoDuration sets the optional parameter "videoDuration": The
// videoDuration parameter filters video search results based on their
// duration. If you specify a value for this parameter, you must also
// set the type parameter's value to video.
//
// Possible values:
//   "any" - Do not filter video search results based on their duration.
// This is the default value.
//   "long" - Only include videos longer than 20 minutes.
//   "medium" - Only include videos that are between four and 20 minutes
// long (inclusive).
//   "short" - Only include videos that are less than four minutes long.
func (c *SearchListCall) VideoDuration(videoDuration string) *SearchListCall {
	c.opt_["videoDuration"] = videoDuration
	return c
}

// VideoEmbeddable sets the optional parameter "videoEmbeddable": The
// videoEmbeddable parameter lets you to restrict a search to only
// videos that can be embedded into a webpage. If you specify a value
// for this parameter, you must also set the type parameter's value to
// video.
//
// Possible values:
//   "any" - Return all videos, embeddable or not.
//   "true" - Only retrieve embeddable videos.
func (c *SearchListCall) VideoEmbeddable(videoEmbeddable string) *SearchListCall {
	c.opt_["videoEmbeddable"] = videoEmbeddable
	return c
}

// VideoLicense sets the optional parameter "videoLicense": The
// videoLicense parameter filters search results to only include videos
// with a particular license. YouTube lets video uploaders choose to
// attach either the Creative Commons license or the standard YouTube
// license to each of their videos. If you specify a value for this
// parameter, you must also set the type parameter's value to video.
//
// Possible values:
//   "any" - Return all videos, regardless of which license they have,
// that match the query parameters.
//   "creativeCommon" - Only return videos that have a Creative Commons
// license. Users can reuse videos with this license in other videos
// that they create. Learn more.
//   "youtube" - Only return videos that have the standard YouTube
// license.
func (c *SearchListCall) VideoLicense(videoLicense string) *SearchListCall {
	c.opt_["videoLicense"] = videoLicense
	return c
}

// VideoSyndicated sets the optional parameter "videoSyndicated": The
// videoSyndicated parameter lets you to restrict a search to only
// videos that can be played outside youtube.com. If you specify a value
// for this parameter, you must also set the type parameter's value to
// video.
//
// Possible values:
//   "any" - Return all videos, syndicated or not.
//   "true" - Only retrieve syndicated videos.
func (c *SearchListCall) VideoSyndicated(videoSyndicated string) *SearchListCall {
	c.opt_["videoSyndicated"] = videoSyndicated
	return c
}

// VideoType sets the optional parameter "videoType": The videoType
// parameter lets you restrict a search to a particular type of videos.
// If you specify a value for this parameter, you must also set the type
// parameter's value to video.
//
// Possible values:
//   "any" - Return all videos.
//   "episode" - Only retrieve episodes of shows.
//   "movie" - Only retrieve movies.
func (c *SearchListCall) VideoType(videoType string) *SearchListCall {
	c.opt_["videoType"] = videoType
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SearchListCall) Fields(s ...googleapi.Field) *SearchListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SearchListCall) IfNoneMatch(entityTag string) *SearchListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SearchListCall) Context(ctx context.Context) *SearchListCall {
	c.ctx_ = ctx
	return c
}

func (c *SearchListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["channelType"]; ok {
		params.Set("channelType", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["eventType"]; ok {
		params.Set("eventType", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["forContentOwner"]; ok {
		params.Set("forContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["forDeveloper"]; ok {
		params.Set("forDeveloper", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["forMine"]; ok {
		params.Set("forMine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["location"]; ok {
		params.Set("location", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["locationRadius"]; ok {
		params.Set("locationRadius", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["order"]; ok {
		params.Set("order", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["publishedAfter"]; ok {
		params.Set("publishedAfter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["publishedBefore"]; ok {
		params.Set("publishedBefore", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["q"]; ok {
		params.Set("q", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["regionCode"]; ok {
		params.Set("regionCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["relatedToVideoId"]; ok {
		params.Set("relatedToVideoId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["relevanceLanguage"]; ok {
		params.Set("relevanceLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["safeSearch"]; ok {
		params.Set("safeSearch", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["topicId"]; ok {
		params.Set("topicId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["type"]; ok {
		params.Set("type", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoCaption"]; ok {
		params.Set("videoCaption", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoCategoryId"]; ok {
		params.Set("videoCategoryId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoDefinition"]; ok {
		params.Set("videoDefinition", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoDimension"]; ok {
		params.Set("videoDimension", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoDuration"]; ok {
		params.Set("videoDuration", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoEmbeddable"]; ok {
		params.Set("videoEmbeddable", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoLicense"]; ok {
		params.Set("videoLicense", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoSyndicated"]; ok {
		params.Set("videoSyndicated", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoType"]; ok {
		params.Set("videoType", fmt.Sprintf("%v", v))
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

// Do executes the "youtube.search.list" call.
// Exactly one of *SearchListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SearchListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SearchListCall) Do() (*SearchListResponse, error) {
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
	ret := &SearchListResponse{
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
	//   "description": "Returns a collection of search results that match the query parameters specified in the API request. By default, a search result set identifies matching video, channel, and playlist resources, but you can also configure queries to only retrieve a specific type of resource.",
	//   "httpMethod": "GET",
	//   "id": "youtube.search.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter indicates that the API response should only contain resources created by the channel",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "channelType": {
	//       "description": "The channelType parameter lets you restrict a search to a particular type of channel.",
	//       "enum": [
	//         "any",
	//         "show"
	//       ],
	//       "enumDescriptions": [
	//         "Return all channels.",
	//         "Only retrieve shows."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "eventType": {
	//       "description": "The eventType parameter restricts a search to broadcast events. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "completed",
	//         "live",
	//         "upcoming"
	//       ],
	//       "enumDescriptions": [
	//         "Only include completed broadcasts.",
	//         "Only include active broadcasts.",
	//         "Only include upcoming broadcasts."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "forContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe forContentOwner parameter restricts the search to only retrieve resources owned by the content owner specified by the onBehalfOfContentOwner parameter. The user must be authenticated using a CMS account linked to the specified content owner and onBehalfOfContentOwner must be provided.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "forDeveloper": {
	//       "description": "The forDeveloper parameter restricts the search to only retrieve videos uploaded via the developer's application or website. The API server uses the request's authorization credentials to identify the developer. Therefore, a developer can restrict results to videos uploaded through the developer's own app or website but not to videos uploaded through other apps or sites.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "forMine": {
	//       "description": "The forMine parameter restricts the search to only retrieve videos owned by the authenticated user. If you set this parameter to true, then the type parameter's value must also be set to video.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "location": {
	//       "description": "The location parameter, in conjunction with the locationRadius parameter, defines a circular geographic area and also restricts a search to videos that specify, in their metadata, a geographic location that falls within that area. The parameter value is a string that specifies latitude/longitude coordinates e.g. (37.42307,-122.08427).\n\n\n- The location parameter value identifies the point at the center of the area.\n- The locationRadius parameter specifies the maximum distance that the location associated with a video can be from that point for the video to still be included in the search results.The API returns an error if your request specifies a value for the location parameter but does not also specify a value for the locationRadius parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "locationRadius": {
	//       "description": "The locationRadius parameter, in conjunction with the location parameter, defines a circular geographic area.\n\nThe parameter value must be a floating point number followed by a measurement unit. Valid measurement units are m, km, ft, and mi. For example, valid parameter values include 1500m, 5km, 10000ft, and 0.75mi. The API does not support locationRadius parameter values larger than 1000 kilometers.\n\nNote: See the definition of the location parameter for more information.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "order": {
	//       "default": "SEARCH_SORT_RELEVANCE",
	//       "description": "The order parameter specifies the method that will be used to order resources in the API response.",
	//       "enum": [
	//         "date",
	//         "rating",
	//         "relevance",
	//         "title",
	//         "videoCount",
	//         "viewCount"
	//       ],
	//       "enumDescriptions": [
	//         "Resources are sorted in reverse chronological order based on the date they were created.",
	//         "Resources are sorted from highest to lowest rating.",
	//         "Resources are sorted based on their relevance to the search query. This is the default value for this parameter.",
	//         "Resources are sorted alphabetically by title.",
	//         "Channels are sorted in descending order of their number of uploaded videos.",
	//         "Resources are sorted from highest to lowest number of views."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more search resource properties that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "publishedAfter": {
	//       "description": "The publishedAfter parameter indicates that the API response should only contain resources created after the specified time. The value is an RFC 3339 formatted date-time value (1970-01-01T00:00:00Z).",
	//       "format": "date-time",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "publishedBefore": {
	//       "description": "The publishedBefore parameter indicates that the API response should only contain resources created before the specified time. The value is an RFC 3339 formatted date-time value (1970-01-01T00:00:00Z).",
	//       "format": "date-time",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "q": {
	//       "description": "The q parameter specifies the query term to search for.\n\nYour request can also use the Boolean NOT (-) and OR (|) operators to exclude videos or to find videos that are associated with one of several search terms. For example, to search for videos matching either \"boating\" or \"sailing\", set the q parameter value to boating|sailing. Similarly, to search for videos matching either \"boating\" or \"sailing\" but not \"fishing\", set the q parameter value to boating|sailing -fishing. Note that the pipe character must be URL-escaped when it is sent in your API request. The URL-escaped value for the pipe character is %7C.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "regionCode": {
	//       "description": "The regionCode parameter instructs the API to return search results for the specified country. The parameter value is an ISO 3166-1 alpha-2 country code.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "relatedToVideoId": {
	//       "description": "The relatedToVideoId parameter retrieves a list of videos that are related to the video that the parameter value identifies. The parameter value must be set to a YouTube video ID and, if you are using this parameter, the type parameter must be set to video.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "relevanceLanguage": {
	//       "description": "The relevanceLanguage parameter instructs the API to return search results that are most relevant to the specified language. The parameter value is typically an ISO 639-1 two-letter language code. However, you should use the values zh-Hans for simplified Chinese and zh-Hant for traditional Chinese. Please note that results in other languages will still be returned if they are highly relevant to the search query term.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "safeSearch": {
	//       "description": "The safeSearch parameter indicates whether the search results should include restricted content as well as standard content.",
	//       "enum": [
	//         "moderate",
	//         "none",
	//         "strict"
	//       ],
	//       "enumDescriptions": [
	//         "YouTube will filter some content from search results and, at the least, will filter content that is restricted in your locale. Based on their content, search results could be removed from search results or demoted in search results. This is the default parameter value.",
	//         "YouTube will not filter the search result set.",
	//         "YouTube will try to exclude all restricted content from the search result set. Based on their content, search results could be removed from search results or demoted in search results."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "topicId": {
	//       "description": "The topicId parameter indicates that the API response should only contain resources associated with the specified topic. The value identifies a Freebase topic ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "type": {
	//       "default": "video,channel,playlist",
	//       "description": "The type parameter restricts a search query to only retrieve a particular type of resource. The value is a comma-separated list of resource types.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoCaption": {
	//       "description": "The videoCaption parameter indicates whether the API should filter video search results based on whether they have captions. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "closedCaption",
	//         "none"
	//       ],
	//       "enumDescriptions": [
	//         "Do not filter results based on caption availability.",
	//         "Only include videos that have captions.",
	//         "Only include videos that do not have captions."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoCategoryId": {
	//       "description": "The videoCategoryId parameter filters video search results based on their category. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoDefinition": {
	//       "description": "The videoDefinition parameter lets you restrict a search to only include either high definition (HD) or standard definition (SD) videos. HD videos are available for playback in at least 720p, though higher resolutions, like 1080p, might also be available. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "high",
	//         "standard"
	//       ],
	//       "enumDescriptions": [
	//         "Return all videos, regardless of their resolution.",
	//         "Only retrieve HD videos.",
	//         "Only retrieve videos in standard definition."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoDimension": {
	//       "description": "The videoDimension parameter lets you restrict a search to only retrieve 2D or 3D videos. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "2d",
	//         "3d",
	//         "any"
	//       ],
	//       "enumDescriptions": [
	//         "Restrict search results to exclude 3D videos.",
	//         "Restrict search results to only include 3D videos.",
	//         "Include both 3D and non-3D videos in returned results. This is the default value."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoDuration": {
	//       "description": "The videoDuration parameter filters video search results based on their duration. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "long",
	//         "medium",
	//         "short"
	//       ],
	//       "enumDescriptions": [
	//         "Do not filter video search results based on their duration. This is the default value.",
	//         "Only include videos longer than 20 minutes.",
	//         "Only include videos that are between four and 20 minutes long (inclusive).",
	//         "Only include videos that are less than four minutes long."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoEmbeddable": {
	//       "description": "The videoEmbeddable parameter lets you to restrict a search to only videos that can be embedded into a webpage. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "true"
	//       ],
	//       "enumDescriptions": [
	//         "Return all videos, embeddable or not.",
	//         "Only retrieve embeddable videos."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoLicense": {
	//       "description": "The videoLicense parameter filters search results to only include videos with a particular license. YouTube lets video uploaders choose to attach either the Creative Commons license or the standard YouTube license to each of their videos. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "creativeCommon",
	//         "youtube"
	//       ],
	//       "enumDescriptions": [
	//         "Return all videos, regardless of which license they have, that match the query parameters.",
	//         "Only return videos that have a Creative Commons license. Users can reuse videos with this license in other videos that they create. Learn more.",
	//         "Only return videos that have the standard YouTube license."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoSyndicated": {
	//       "description": "The videoSyndicated parameter lets you to restrict a search to only videos that can be played outside youtube.com. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "true"
	//       ],
	//       "enumDescriptions": [
	//         "Return all videos, syndicated or not.",
	//         "Only retrieve syndicated videos."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoType": {
	//       "description": "The videoType parameter lets you restrict a search to a particular type of videos. If you specify a value for this parameter, you must also set the type parameter's value to video.",
	//       "enum": [
	//         "any",
	//         "episode",
	//         "movie"
	//       ],
	//       "enumDescriptions": [
	//         "Return all videos.",
	//         "Only retrieve episodes of shows.",
	//         "Only retrieve movies."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "search",
	//   "response": {
	//     "$ref": "SearchListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.subscriptions.delete":

type SubscriptionsDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a subscription.
func (r *SubscriptionsService) Delete(id string) *SubscriptionsDeleteCall {
	c := &SubscriptionsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SubscriptionsDeleteCall) Fields(s ...googleapi.Field) *SubscriptionsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SubscriptionsDeleteCall) Context(ctx context.Context) *SubscriptionsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *SubscriptionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "subscriptions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.subscriptions.delete" call.
func (c *SubscriptionsDeleteCall) Do() error {
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
	//   "description": "Deletes a subscription.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.subscriptions.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube subscription ID for the resource that is being deleted. In a subscription resource, the id property specifies the YouTube subscription ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "subscriptions",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.subscriptions.insert":

type SubscriptionsInsertCall struct {
	s            *Service
	part         string
	subscription *Subscription
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Insert: Adds a subscription for the authenticated user's channel.
func (r *SubscriptionsService) Insert(part string, subscription *Subscription) *SubscriptionsInsertCall {
	c := &SubscriptionsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.subscription = subscription
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SubscriptionsInsertCall) Fields(s ...googleapi.Field) *SubscriptionsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SubscriptionsInsertCall) Context(ctx context.Context) *SubscriptionsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *SubscriptionsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.subscription)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "subscriptions")
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

// Do executes the "youtube.subscriptions.insert" call.
// Exactly one of *Subscription or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Subscription.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *SubscriptionsInsertCall) Do() (*Subscription, error) {
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
	ret := &Subscription{
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
	//   "description": "Adds a subscription for the authenticated user's channel.",
	//   "httpMethod": "POST",
	//   "id": "youtube.subscriptions.insert",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "subscriptions",
	//   "request": {
	//     "$ref": "Subscription"
	//   },
	//   "response": {
	//     "$ref": "Subscription"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.subscriptions.list":

type SubscriptionsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns subscription resources that match the API request
// criteria.
func (r *SubscriptionsService) List(part string) *SubscriptionsListCall {
	c := &SubscriptionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// ChannelId sets the optional parameter "channelId": The channelId
// parameter specifies a YouTube channel ID. The API will only return
// that channel's subscriptions.
func (c *SubscriptionsListCall) ChannelId(channelId string) *SubscriptionsListCall {
	c.opt_["channelId"] = channelId
	return c
}

// ForChannelId sets the optional parameter "forChannelId": The
// forChannelId parameter specifies a comma-separated list of channel
// IDs. The API response will then only contain subscriptions matching
// those channels.
func (c *SubscriptionsListCall) ForChannelId(forChannelId string) *SubscriptionsListCall {
	c.opt_["forChannelId"] = forChannelId
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube subscription ID(s) for the
// resource(s) that are being retrieved. In a subscription resource, the
// id property specifies the YouTube subscription ID.
func (c *SubscriptionsListCall) Id(id string) *SubscriptionsListCall {
	c.opt_["id"] = id
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
func (c *SubscriptionsListCall) MaxResults(maxResults int64) *SubscriptionsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Mine sets the optional parameter "mine": Set this parameter's value
// to true to retrieve a feed of the authenticated user's subscriptions.
func (c *SubscriptionsListCall) Mine(mine bool) *SubscriptionsListCall {
	c.opt_["mine"] = mine
	return c
}

// MySubscribers sets the optional parameter "mySubscribers": Set this
// parameter's value to true to retrieve a feed of the subscribers of
// the authenticated user.
func (c *SubscriptionsListCall) MySubscribers(mySubscribers bool) *SubscriptionsListCall {
	c.opt_["mySubscribers"] = mySubscribers
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *SubscriptionsListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *SubscriptionsListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *SubscriptionsListCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *SubscriptionsListCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Order sets the optional parameter "order": The order parameter
// specifies the method that will be used to sort resources in the API
// response.
//
// Possible values:
//   "alphabetical" - Sort alphabetically.
//   "relevance" - Sort by relevance.
//   "unread" - Sort by order of activity.
func (c *SubscriptionsListCall) Order(order string) *SubscriptionsListCall {
	c.opt_["order"] = order
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
func (c *SubscriptionsListCall) PageToken(pageToken string) *SubscriptionsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SubscriptionsListCall) Fields(s ...googleapi.Field) *SubscriptionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SubscriptionsListCall) IfNoneMatch(entityTag string) *SubscriptionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SubscriptionsListCall) Context(ctx context.Context) *SubscriptionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *SubscriptionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["channelId"]; ok {
		params.Set("channelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["forChannelId"]; ok {
		params.Set("forChannelId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mine"]; ok {
		params.Set("mine", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mySubscribers"]; ok {
		params.Set("mySubscribers", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["order"]; ok {
		params.Set("order", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "subscriptions")
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

// Do executes the "youtube.subscriptions.list" call.
// Exactly one of *SubscriptionListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SubscriptionListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SubscriptionsListCall) Do() (*SubscriptionListResponse, error) {
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
	ret := &SubscriptionListResponse{
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
	//   "description": "Returns subscription resources that match the API request criteria.",
	//   "httpMethod": "GET",
	//   "id": "youtube.subscriptions.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter specifies a YouTube channel ID. The API will only return that channel's subscriptions.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "forChannelId": {
	//       "description": "The forChannelId parameter specifies a comma-separated list of channel IDs. The API response will then only contain subscriptions matching those channels.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube subscription ID(s) for the resource(s) that are being retrieved. In a subscription resource, the id property specifies the YouTube subscription ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "mine": {
	//       "description": "Set this parameter's value to true to retrieve a feed of the authenticated user's subscriptions.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "mySubscribers": {
	//       "description": "Set this parameter's value to true to retrieve a feed of the subscribers of the authenticated user.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "order": {
	//       "default": "SUBSCRIPTION_ORDER_RELEVANCE",
	//       "description": "The order parameter specifies the method that will be used to sort resources in the API response.",
	//       "enum": [
	//         "alphabetical",
	//         "relevance",
	//         "unread"
	//       ],
	//       "enumDescriptions": [
	//         "Sort alphabetically.",
	//         "Sort by relevance.",
	//         "Sort by order of activity."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more subscription resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a subscription resource, the snippet property contains other properties, such as a display title for the subscription. If you set part=snippet, the API response will also contain all of those nested properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "subscriptions",
	//   "response": {
	//     "$ref": "SubscriptionListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.thumbnails.set":

type ThumbnailsSetCall struct {
	s          *Service
	videoId    string
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Set: Uploads a custom video thumbnail to YouTube and sets it for a
// video.
func (r *ThumbnailsService) Set(videoId string) *ThumbnailsSetCall {
	c := &ThumbnailsSetCall{s: r.s, opt_: make(map[string]interface{})}
	c.videoId = videoId
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *ThumbnailsSetCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *ThumbnailsSetCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *ThumbnailsSetCall) Media(r io.Reader) *ThumbnailsSetCall {
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
func (c *ThumbnailsSetCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *ThumbnailsSetCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *ThumbnailsSetCall) ProgressUpdater(pu googleapi.ProgressUpdater) *ThumbnailsSetCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ThumbnailsSetCall) Fields(s ...googleapi.Field) *ThumbnailsSetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *ThumbnailsSetCall) Context(ctx context.Context) *ThumbnailsSetCall {
	c.ctx_ = ctx
	return c
}

func (c *ThumbnailsSetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("videoId", fmt.Sprintf("%v", c.videoId))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "thumbnails/set")
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

// Do executes the "youtube.thumbnails.set" call.
// Exactly one of *ThumbnailSetResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ThumbnailSetResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ThumbnailsSetCall) Do() (*ThumbnailSetResponse, error) {
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
	ret := &ThumbnailSetResponse{
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
	//   "description": "Uploads a custom video thumbnail to YouTube and sets it for a video.",
	//   "httpMethod": "POST",
	//   "id": "youtube.thumbnails.set",
	//   "mediaUpload": {
	//     "accept": [
	//       "application/octet-stream",
	//       "image/jpeg",
	//       "image/png"
	//     ],
	//     "maxSize": "2MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/thumbnails/set"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/thumbnails/set"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "videoId"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "The videoId parameter specifies a YouTube video ID for which the custom video thumbnail is being provided.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "thumbnails/set",
	//   "response": {
	//     "$ref": "ThumbnailSetResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.upload",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.videoAbuseReportReasons.list":

type VideoAbuseReportReasonsListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of abuse reasons that can be used for reporting
// abusive videos.
func (r *VideoAbuseReportReasonsService) List(part string) *VideoAbuseReportReasonsListCall {
	c := &VideoAbuseReportReasonsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Hl sets the optional parameter "hl": The hl parameter specifies the
// language that should be used for text values in the API response.
func (c *VideoAbuseReportReasonsListCall) Hl(hl string) *VideoAbuseReportReasonsListCall {
	c.opt_["hl"] = hl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideoAbuseReportReasonsListCall) Fields(s ...googleapi.Field) *VideoAbuseReportReasonsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VideoAbuseReportReasonsListCall) IfNoneMatch(entityTag string) *VideoAbuseReportReasonsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideoAbuseReportReasonsListCall) Context(ctx context.Context) *VideoAbuseReportReasonsListCall {
	c.ctx_ = ctx
	return c
}

func (c *VideoAbuseReportReasonsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videoAbuseReportReasons")
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

// Do executes the "youtube.videoAbuseReportReasons.list" call.
// Exactly one of *VideoAbuseReportReasonListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *VideoAbuseReportReasonListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *VideoAbuseReportReasonsListCall) Do() (*VideoAbuseReportReasonListResponse, error) {
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
	ret := &VideoAbuseReportReasonListResponse{
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
	//   "description": "Returns a list of abuse reasons that can be used for reporting abusive videos.",
	//   "httpMethod": "GET",
	//   "id": "youtube.videoAbuseReportReasons.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "hl": {
	//       "default": "en_US",
	//       "description": "The hl parameter specifies the language that should be used for text values in the API response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the videoCategory resource parts that the API response will include. Supported values are id and snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "videoAbuseReportReasons",
	//   "response": {
	//     "$ref": "VideoAbuseReportReasonListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly"
	//   ]
	// }

}

// method id "youtube.videoCategories.list":

type VideoCategoriesListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of categories that can be associated with
// YouTube videos.
func (r *VideoCategoriesService) List(part string) *VideoCategoriesListCall {
	c := &VideoCategoriesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Hl sets the optional parameter "hl": The hl parameter specifies the
// language that should be used for text values in the API response.
func (c *VideoCategoriesListCall) Hl(hl string) *VideoCategoriesListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of video category IDs for the resources that you
// are retrieving.
func (c *VideoCategoriesListCall) Id(id string) *VideoCategoriesListCall {
	c.opt_["id"] = id
	return c
}

// RegionCode sets the optional parameter "regionCode": The regionCode
// parameter instructs the API to return the list of video categories
// available in the specified country. The parameter value is an ISO
// 3166-1 alpha-2 country code.
func (c *VideoCategoriesListCall) RegionCode(regionCode string) *VideoCategoriesListCall {
	c.opt_["regionCode"] = regionCode
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideoCategoriesListCall) Fields(s ...googleapi.Field) *VideoCategoriesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VideoCategoriesListCall) IfNoneMatch(entityTag string) *VideoCategoriesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideoCategoriesListCall) Context(ctx context.Context) *VideoCategoriesListCall {
	c.ctx_ = ctx
	return c
}

func (c *VideoCategoriesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["regionCode"]; ok {
		params.Set("regionCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videoCategories")
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

// Do executes the "youtube.videoCategories.list" call.
// Exactly one of *VideoCategoryListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *VideoCategoryListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VideoCategoriesListCall) Do() (*VideoCategoryListResponse, error) {
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
	ret := &VideoCategoryListResponse{
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
	//   "description": "Returns a list of categories that can be associated with YouTube videos.",
	//   "httpMethod": "GET",
	//   "id": "youtube.videoCategories.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "hl": {
	//       "default": "en_US",
	//       "description": "The hl parameter specifies the language that should be used for text values in the API response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of video category IDs for the resources that you are retrieving.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies the videoCategory resource properties that the API response will include. Set the parameter value to snippet.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "regionCode": {
	//       "description": "The regionCode parameter instructs the API to return the list of video categories available in the specified country. The parameter value is an ISO 3166-1 alpha-2 country code.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "videoCategories",
	//   "response": {
	//     "$ref": "VideoCategoryListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.delete":

type VideosDeleteCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Delete: Deletes a YouTube video.
func (r *VideosService) Delete(id string) *VideosDeleteCall {
	c := &VideosDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *VideosDeleteCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosDeleteCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosDeleteCall) Fields(s ...googleapi.Field) *VideosDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosDeleteCall) Context(ctx context.Context) *VideosDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.videos.delete" call.
func (c *VideosDeleteCall) Do() error {
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
	//   "description": "Deletes a YouTube video.",
	//   "httpMethod": "DELETE",
	//   "id": "youtube.videos.delete",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube video ID for the resource that is being deleted. In a video resource, the id property specifies the video's ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.getRating":

type VideosGetRatingCall struct {
	s    *Service
	id   string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// GetRating: Retrieves the ratings that the authorized user gave to a
// list of specified videos.
func (r *VideosService) GetRating(id string) *VideosGetRatingCall {
	c := &VideosGetRatingCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *VideosGetRatingCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosGetRatingCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosGetRatingCall) Fields(s ...googleapi.Field) *VideosGetRatingCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VideosGetRatingCall) IfNoneMatch(entityTag string) *VideosGetRatingCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosGetRatingCall) Context(ctx context.Context) *VideosGetRatingCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosGetRatingCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos/getRating")
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

// Do executes the "youtube.videos.getRating" call.
// Exactly one of *VideoGetRatingResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *VideoGetRatingResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VideosGetRatingCall) Do() (*VideoGetRatingResponse, error) {
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
	ret := &VideoGetRatingResponse{
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
	//   "description": "Retrieves the ratings that the authorized user gave to a list of specified videos.",
	//   "httpMethod": "GET",
	//   "id": "youtube.videos.getRating",
	//   "parameterOrder": [
	//     "id"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube video ID(s) for the resource(s) for which you are retrieving rating data. In a video resource, the id property specifies the video's ID.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos/getRating",
	//   "response": {
	//     "$ref": "VideoGetRatingResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.insert":

type VideosInsertCall struct {
	s          *Service
	part       string
	video      *Video
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Insert: Uploads a video to YouTube and optionally sets the video's
// metadata.
func (r *VideosService) Insert(part string, video *Video) *VideosInsertCall {
	c := &VideosInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.video = video
	return c
}

// AutoLevels sets the optional parameter "autoLevels": The autoLevels
// parameter indicates whether YouTube should automatically enhance the
// video's lighting and color.
func (c *VideosInsertCall) AutoLevels(autoLevels bool) *VideosInsertCall {
	c.opt_["autoLevels"] = autoLevels
	return c
}

// NotifySubscribers sets the optional parameter "notifySubscribers":
// The notifySubscribers parameter indicates whether YouTube should send
// a notification about the new video to users who subscribe to the
// video's channel. A parameter value of True indicates that subscribers
// will be notified of newly uploaded videos. However, a channel owner
// who is uploading many videos might prefer to set the value to False
// to avoid sending a notification about each new video to the channel's
// subscribers.
func (c *VideosInsertCall) NotifySubscribers(notifySubscribers bool) *VideosInsertCall {
	c.opt_["notifySubscribers"] = notifySubscribers
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *VideosInsertCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosInsertCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// OnBehalfOfContentOwnerChannel sets the optional parameter
// "onBehalfOfContentOwnerChannel": This parameter can only be used in a
// properly authorized request. Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwnerChannel parameter specifies the YouTube
// channel ID of the channel to which a video is being added. This
// parameter is required when a request specifies a value for the
// onBehalfOfContentOwner parameter, and it can only be used in
// conjunction with that parameter. In addition, the request must be
// authorized using a CMS account that is linked to the content owner
// that the onBehalfOfContentOwner parameter specifies. Finally, the
// channel that the onBehalfOfContentOwnerChannel parameter value
// specifies must be linked to the content owner that the
// onBehalfOfContentOwner parameter specifies.
//
// This parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and perform actions on behalf of the channel
// specified in the parameter value, without having to provide
// authentication credentials for each separate channel.
func (c *VideosInsertCall) OnBehalfOfContentOwnerChannel(onBehalfOfContentOwnerChannel string) *VideosInsertCall {
	c.opt_["onBehalfOfContentOwnerChannel"] = onBehalfOfContentOwnerChannel
	return c
}

// Stabilize sets the optional parameter "stabilize": The stabilize
// parameter indicates whether YouTube should adjust the video to remove
// shaky camera motions.
func (c *VideosInsertCall) Stabilize(stabilize bool) *VideosInsertCall {
	c.opt_["stabilize"] = stabilize
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *VideosInsertCall) Media(r io.Reader) *VideosInsertCall {
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
func (c *VideosInsertCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *VideosInsertCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *VideosInsertCall) ProgressUpdater(pu googleapi.ProgressUpdater) *VideosInsertCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosInsertCall) Fields(s ...googleapi.Field) *VideosInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *VideosInsertCall) Context(ctx context.Context) *VideosInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.video)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["autoLevels"]; ok {
		params.Set("autoLevels", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["notifySubscribers"]; ok {
		params.Set("notifySubscribers", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwnerChannel"]; ok {
		params.Set("onBehalfOfContentOwnerChannel", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["stabilize"]; ok {
		params.Set("stabilize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos")
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

// Do executes the "youtube.videos.insert" call.
// Exactly one of *Video or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Video.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *VideosInsertCall) Do() (*Video, error) {
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
	ret := &Video{
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
	//   "description": "Uploads a video to YouTube and optionally sets the video's metadata.",
	//   "httpMethod": "POST",
	//   "id": "youtube.videos.insert",
	//   "mediaUpload": {
	//     "accept": [
	//       "application/octet-stream",
	//       "video/*"
	//     ],
	//     "maxSize": "64GB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/videos"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/videos"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "autoLevels": {
	//       "description": "The autoLevels parameter indicates whether YouTube should automatically enhance the video's lighting and color.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "notifySubscribers": {
	//       "default": "true",
	//       "description": "The notifySubscribers parameter indicates whether YouTube should send a notification about the new video to users who subscribe to the video's channel. A parameter value of True indicates that subscribers will be notified of newly uploaded videos. However, a channel owner who is uploading many videos might prefer to set the value to False to avoid sending a notification about each new video to the channel's subscribers.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwnerChannel": {
	//       "description": "This parameter can only be used in a properly authorized request. Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwnerChannel parameter specifies the YouTube channel ID of the channel to which a video is being added. This parameter is required when a request specifies a value for the onBehalfOfContentOwner parameter, and it can only be used in conjunction with that parameter. In addition, the request must be authorized using a CMS account that is linked to the content owner that the onBehalfOfContentOwner parameter specifies. Finally, the channel that the onBehalfOfContentOwnerChannel parameter value specifies must be linked to the content owner that the onBehalfOfContentOwner parameter specifies.\n\nThis parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and perform actions on behalf of the channel specified in the parameter value, without having to provide authentication credentials for each separate channel.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nNote that not all parts contain properties that can be set when inserting or updating a video. For example, the statistics object encapsulates statistics that YouTube calculates for a video and does not contain values that you can set or modify. If the parameter value specifies a part that does not contain mutable values, that part will still be included in the API response.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "stabilize": {
	//       "description": "The stabilize parameter indicates whether YouTube should adjust the video to remove shaky camera motions.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "videos",
	//   "request": {
	//     "$ref": "Video"
	//   },
	//   "response": {
	//     "$ref": "Video"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.upload",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.videos.list":

type VideosListCall struct {
	s    *Service
	part string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns a list of videos that match the API request parameters.
func (r *VideosService) List(part string) *VideosListCall {
	c := &VideosListCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	return c
}

// Chart sets the optional parameter "chart": The chart parameter
// identifies the chart that you want to retrieve.
//
// Possible values:
//   "mostPopular" - Return the most popular videos for the specified
// content region and video category.
func (c *VideosListCall) Chart(chart string) *VideosListCall {
	c.opt_["chart"] = chart
	return c
}

// Hl sets the optional parameter "hl": The hl parameter instructs the
// API to retrieve localized resource metadata for a specific
// application language that the YouTube website supports. The parameter
// value must be a language code included in the list returned by the
// i18nLanguages.list method.
//
// If localized resource details are available in that language, the
// resource's snippet.localized object will contain the localized
// values. However, if localized details are not available, the
// snippet.localized object will contain resource details in the
// resource's default language.
func (c *VideosListCall) Hl(hl string) *VideosListCall {
	c.opt_["hl"] = hl
	return c
}

// Id sets the optional parameter "id": The id parameter specifies a
// comma-separated list of the YouTube video ID(s) for the resource(s)
// that are being retrieved. In a video resource, the id property
// specifies the video's ID.
func (c *VideosListCall) Id(id string) *VideosListCall {
	c.opt_["id"] = id
	return c
}

// Locale sets the optional parameter "locale": DEPRECATED
func (c *VideosListCall) Locale(locale string) *VideosListCall {
	c.opt_["locale"] = locale
	return c
}

// MaxResults sets the optional parameter "maxResults": The maxResults
// parameter specifies the maximum number of items that should be
// returned in the result set.
//
// Note: This parameter is supported for use in conjunction with the
// myRating parameter, but it is not supported for use in conjunction
// with the id parameter.
func (c *VideosListCall) MaxResults(maxResults int64) *VideosListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// MyRating sets the optional parameter "myRating": Set this parameter's
// value to like or dislike to instruct the API to only return videos
// liked or disliked by the authenticated user.
//
// Possible values:
//   "dislike" - Returns only videos disliked by the authenticated user.
//   "like" - Returns only video liked by the authenticated user.
func (c *VideosListCall) MyRating(myRating string) *VideosListCall {
	c.opt_["myRating"] = myRating
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *VideosListCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosListCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// PageToken sets the optional parameter "pageToken": The pageToken
// parameter identifies a specific page in the result set that should be
// returned. In an API response, the nextPageToken and prevPageToken
// properties identify other pages that could be retrieved.
//
// Note: This parameter is supported for use in conjunction with the
// myRating parameter, but it is not supported for use in conjunction
// with the id parameter.
func (c *VideosListCall) PageToken(pageToken string) *VideosListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// RegionCode sets the optional parameter "regionCode": The regionCode
// parameter instructs the API to select a video chart available in the
// specified region. This parameter can only be used in conjunction with
// the chart parameter. The parameter value is an ISO 3166-1 alpha-2
// country code.
func (c *VideosListCall) RegionCode(regionCode string) *VideosListCall {
	c.opt_["regionCode"] = regionCode
	return c
}

// VideoCategoryId sets the optional parameter "videoCategoryId": The
// videoCategoryId parameter identifies the video category for which the
// chart should be retrieved. This parameter can only be used in
// conjunction with the chart parameter. By default, charts are not
// restricted to a particular category.
func (c *VideosListCall) VideoCategoryId(videoCategoryId string) *VideosListCall {
	c.opt_["videoCategoryId"] = videoCategoryId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosListCall) Fields(s ...googleapi.Field) *VideosListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VideosListCall) IfNoneMatch(entityTag string) *VideosListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosListCall) Context(ctx context.Context) *VideosListCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["chart"]; ok {
		params.Set("chart", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["hl"]; ok {
		params.Set("hl", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["id"]; ok {
		params.Set("id", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["locale"]; ok {
		params.Set("locale", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["myRating"]; ok {
		params.Set("myRating", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["regionCode"]; ok {
		params.Set("regionCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoCategoryId"]; ok {
		params.Set("videoCategoryId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos")
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

// Do executes the "youtube.videos.list" call.
// Exactly one of *VideoListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *VideoListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VideosListCall) Do() (*VideoListResponse, error) {
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
	ret := &VideoListResponse{
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
	//   "description": "Returns a list of videos that match the API request parameters.",
	//   "httpMethod": "GET",
	//   "id": "youtube.videos.list",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "chart": {
	//       "description": "The chart parameter identifies the chart that you want to retrieve.",
	//       "enum": [
	//         "mostPopular"
	//       ],
	//       "enumDescriptions": [
	//         "Return the most popular videos for the specified content region and video category."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "hl": {
	//       "description": "The hl parameter instructs the API to retrieve localized resource metadata for a specific application language that the YouTube website supports. The parameter value must be a language code included in the list returned by the i18nLanguages.list method.\n\nIf localized resource details are available in that language, the resource's snippet.localized object will contain the localized values. However, if localized details are not available, the snippet.localized object will contain resource details in the resource's default language.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "id": {
	//       "description": "The id parameter specifies a comma-separated list of the YouTube video ID(s) for the resource(s) that are being retrieved. In a video resource, the id property specifies the video's ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "locale": {
	//       "description": "DEPRECATED",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "5",
	//       "description": "The maxResults parameter specifies the maximum number of items that should be returned in the result set.\n\nNote: This parameter is supported for use in conjunction with the myRating parameter, but it is not supported for use in conjunction with the id parameter.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "myRating": {
	//       "description": "Set this parameter's value to like or dislike to instruct the API to only return videos liked or disliked by the authenticated user.",
	//       "enum": [
	//         "dislike",
	//         "like"
	//       ],
	//       "enumDescriptions": [
	//         "Returns only videos disliked by the authenticated user.",
	//         "Returns only video liked by the authenticated user."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The pageToken parameter identifies a specific page in the result set that should be returned. In an API response, the nextPageToken and prevPageToken properties identify other pages that could be retrieved.\n\nNote: This parameter is supported for use in conjunction with the myRating parameter, but it is not supported for use in conjunction with the id parameter.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter specifies a comma-separated list of one or more video resource properties that the API response will include.\n\nIf the parameter identifies a property that contains child properties, the child properties will be included in the response. For example, in a video resource, the snippet property contains the channelId, title, description, tags, and categoryId properties. As such, if you set part=snippet, the API response will contain all of those properties.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "regionCode": {
	//       "description": "The regionCode parameter instructs the API to select a video chart available in the specified region. This parameter can only be used in conjunction with the chart parameter. The parameter value is an ISO 3166-1 alpha-2 country code.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoCategoryId": {
	//       "default": "0",
	//       "description": "The videoCategoryId parameter identifies the video category for which the chart should be retrieved. This parameter can only be used in conjunction with the chart parameter. By default, charts are not restricted to a particular category.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos",
	//   "response": {
	//     "$ref": "VideoListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.readonly",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.rate":

type VideosRateCall struct {
	s      *Service
	id     string
	rating string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Rate: Add a like or dislike rating to a video or remove a rating from
// a video.
func (r *VideosService) Rate(id string, rating string) *VideosRateCall {
	c := &VideosRateCall{s: r.s, opt_: make(map[string]interface{})}
	c.id = id
	c.rating = rating
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosRateCall) Fields(s ...googleapi.Field) *VideosRateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosRateCall) Context(ctx context.Context) *VideosRateCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosRateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("id", fmt.Sprintf("%v", c.id))
	params.Set("rating", fmt.Sprintf("%v", c.rating))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos/rate")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.videos.rate" call.
func (c *VideosRateCall) Do() error {
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
	//   "description": "Add a like or dislike rating to a video or remove a rating from a video.",
	//   "httpMethod": "POST",
	//   "id": "youtube.videos.rate",
	//   "parameterOrder": [
	//     "id",
	//     "rating"
	//   ],
	//   "parameters": {
	//     "id": {
	//       "description": "The id parameter specifies the YouTube video ID of the video that is being rated or having its rating removed.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "rating": {
	//       "description": "Specifies the rating to record.",
	//       "enum": [
	//         "dislike",
	//         "like",
	//         "none"
	//       ],
	//       "enumDescriptions": [
	//         "Records that the authenticated user disliked the video.",
	//         "Records that the authenticated user liked the video.",
	//         "Removes any rating that the authenticated user had previously set for the video."
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos/rate",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.reportAbuse":

type VideosReportAbuseCall struct {
	s                *Service
	videoabusereport *VideoAbuseReport
	opt_             map[string]interface{}
	ctx_             context.Context
}

// ReportAbuse: Report abuse for a video.
func (r *VideosService) ReportAbuse(videoabusereport *VideoAbuseReport) *VideosReportAbuseCall {
	c := &VideosReportAbuseCall{s: r.s, opt_: make(map[string]interface{})}
	c.videoabusereport = videoabusereport
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *VideosReportAbuseCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosReportAbuseCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosReportAbuseCall) Fields(s ...googleapi.Field) *VideosReportAbuseCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosReportAbuseCall) Context(ctx context.Context) *VideosReportAbuseCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosReportAbuseCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.videoabusereport)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos/reportAbuse")
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

// Do executes the "youtube.videos.reportAbuse" call.
func (c *VideosReportAbuseCall) Do() error {
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
	//   "description": "Report abuse for a video.",
	//   "httpMethod": "POST",
	//   "id": "youtube.videos.reportAbuse",
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos/reportAbuse",
	//   "request": {
	//     "$ref": "VideoAbuseReport"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.videos.update":

type VideosUpdateCall struct {
	s     *Service
	part  string
	video *Video
	opt_  map[string]interface{}
	ctx_  context.Context
}

// Update: Updates a video's metadata.
func (r *VideosService) Update(part string, video *Video) *VideosUpdateCall {
	c := &VideosUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.part = part
	c.video = video
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The actual CMS account that the user
// authenticates with must be linked to the specified YouTube content
// owner.
func (c *VideosUpdateCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *VideosUpdateCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VideosUpdateCall) Fields(s ...googleapi.Field) *VideosUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VideosUpdateCall) Context(ctx context.Context) *VideosUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *VideosUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.video)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("part", fmt.Sprintf("%v", c.part))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "videos")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.videos.update" call.
// Exactly one of *Video or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Video.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *VideosUpdateCall) Do() (*Video, error) {
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
	ret := &Video{
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
	//   "description": "Updates a video's metadata.",
	//   "httpMethod": "PUT",
	//   "id": "youtube.videos.update",
	//   "parameterOrder": [
	//     "part"
	//   ],
	//   "parameters": {
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The actual CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "part": {
	//       "description": "The part parameter serves two purposes in this operation. It identifies the properties that the write operation will set as well as the properties that the API response will include.\n\nNote that this method will override the existing values for all of the mutable properties that are contained in any parts that the parameter value specifies. For example, a video's privacy setting is contained in the status part. As such, if your request is updating a private video, and the request's part parameter value includes the status part, the video's privacy setting will be updated to whatever value the request body specifies. If the request body does not specify a value, the existing privacy setting will be removed and the video will revert to the default privacy setting.\n\nIn addition, not all parts contain properties that can be set when inserting or updating a video. For example, the statistics object encapsulates statistics that YouTube calculates for a video and does not contain values that you can set or modify. If the parameter value specifies a part that does not contain mutable values, that part will still be included in the API response.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "videos",
	//   "request": {
	//     "$ref": "Video"
	//   },
	//   "response": {
	//     "$ref": "Video"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}

// method id "youtube.watermarks.set":

type WatermarksSetCall struct {
	s               *Service
	channelId       string
	invideobranding *InvideoBranding
	opt_            map[string]interface{}
	media_          io.Reader
	resumable_      googleapi.SizeReaderAt
	mediaType_      string
	protocol_       string
	ctx_            context.Context
}

// Set: Uploads a watermark image to YouTube and sets it for a channel.
func (r *WatermarksService) Set(channelId string, invideobranding *InvideoBranding) *WatermarksSetCall {
	c := &WatermarksSetCall{s: r.s, opt_: make(map[string]interface{})}
	c.channelId = channelId
	c.invideobranding = invideobranding
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *WatermarksSetCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *WatermarksSetCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *WatermarksSetCall) Media(r io.Reader) *WatermarksSetCall {
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
func (c *WatermarksSetCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *WatermarksSetCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *WatermarksSetCall) ProgressUpdater(pu googleapi.ProgressUpdater) *WatermarksSetCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *WatermarksSetCall) Fields(s ...googleapi.Field) *WatermarksSetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *WatermarksSetCall) Context(ctx context.Context) *WatermarksSetCall {
	c.ctx_ = ctx
	return c
}

func (c *WatermarksSetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.invideobranding)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("channelId", fmt.Sprintf("%v", c.channelId))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "watermarks/set")
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

// Do executes the "youtube.watermarks.set" call.
func (c *WatermarksSetCall) Do() error {
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
	//   "description": "Uploads a watermark image to YouTube and sets it for a channel.",
	//   "httpMethod": "POST",
	//   "id": "youtube.watermarks.set",
	//   "mediaUpload": {
	//     "accept": [
	//       "application/octet-stream",
	//       "image/jpeg",
	//       "image/png"
	//     ],
	//     "maxSize": "10MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/youtube/v3/watermarks/set"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/youtube/v3/watermarks/set"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "channelId"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter specifies the YouTube channel ID for which the watermark is being provided.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "watermarks/set",
	//   "request": {
	//     "$ref": "InvideoBranding"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtube.upload",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "youtube.watermarks.unset":

type WatermarksUnsetCall struct {
	s         *Service
	channelId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Unset: Deletes a channel's watermark image.
func (r *WatermarksService) Unset(channelId string) *WatermarksUnsetCall {
	c := &WatermarksUnsetCall{s: r.s, opt_: make(map[string]interface{})}
	c.channelId = channelId
	return c
}

// OnBehalfOfContentOwner sets the optional parameter
// "onBehalfOfContentOwner": Note: This parameter is intended
// exclusively for YouTube content partners.
//
// The onBehalfOfContentOwner parameter indicates that the request's
// authorization credentials identify a YouTube CMS user who is acting
// on behalf of the content owner specified in the parameter value. This
// parameter is intended for YouTube content partners that own and
// manage many different YouTube channels. It allows content owners to
// authenticate once and get access to all their video and channel data,
// without having to provide authentication credentials for each
// individual channel. The CMS account that the user authenticates with
// must be linked to the specified YouTube content owner.
func (c *WatermarksUnsetCall) OnBehalfOfContentOwner(onBehalfOfContentOwner string) *WatermarksUnsetCall {
	c.opt_["onBehalfOfContentOwner"] = onBehalfOfContentOwner
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *WatermarksUnsetCall) Fields(s ...googleapi.Field) *WatermarksUnsetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *WatermarksUnsetCall) Context(ctx context.Context) *WatermarksUnsetCall {
	c.ctx_ = ctx
	return c
}

func (c *WatermarksUnsetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("channelId", fmt.Sprintf("%v", c.channelId))
	if v, ok := c.opt_["onBehalfOfContentOwner"]; ok {
		params.Set("onBehalfOfContentOwner", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "watermarks/unset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "youtube.watermarks.unset" call.
func (c *WatermarksUnsetCall) Do() error {
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
	//   "description": "Deletes a channel's watermark image.",
	//   "httpMethod": "POST",
	//   "id": "youtube.watermarks.unset",
	//   "parameterOrder": [
	//     "channelId"
	//   ],
	//   "parameters": {
	//     "channelId": {
	//       "description": "The channelId parameter specifies the YouTube channel ID for which the watermark is being unset.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "onBehalfOfContentOwner": {
	//       "description": "Note: This parameter is intended exclusively for YouTube content partners.\n\nThe onBehalfOfContentOwner parameter indicates that the request's authorization credentials identify a YouTube CMS user who is acting on behalf of the content owner specified in the parameter value. This parameter is intended for YouTube content partners that own and manage many different YouTube channels. It allows content owners to authenticate once and get access to all their video and channel data, without having to provide authentication credentials for each individual channel. The CMS account that the user authenticates with must be linked to the specified YouTube content owner.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "watermarks/unset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/youtube",
	//     "https://www.googleapis.com/auth/youtube.force-ssl",
	//     "https://www.googleapis.com/auth/youtubepartner"
	//   ]
	// }

}
