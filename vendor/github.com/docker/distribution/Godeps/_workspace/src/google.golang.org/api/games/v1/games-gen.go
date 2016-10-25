// Package games provides access to the Google Play Game Services API.
//
// See https://developers.google.com/games/services/
//
// Usage example:
//
//   import "google.golang.org/api/games/v1"
//   ...
//   gamesService, err := games.New(oauthHttpClient)
package games // import "google.golang.org/api/games/v1"

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

const apiId = "games:v1"
const apiName = "games"
const apiVersion = "v1"
const basePath = "https://www.googleapis.com/games/v1/"

// OAuth2 scopes used by this API.
const (
	// View and manage its own configuration data in your Google Drive
	DriveAppdataScope = "https://www.googleapis.com/auth/drive.appdata"

	// Share your Google+ profile information and view and manage your game
	// activity
	GamesScope = "https://www.googleapis.com/auth/games"

	// Know your basic profile info and list of people in your circles.
	PlusLoginScope = "https://www.googleapis.com/auth/plus.login"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.AchievementDefinitions = NewAchievementDefinitionsService(s)
	s.Achievements = NewAchievementsService(s)
	s.Applications = NewApplicationsService(s)
	s.Events = NewEventsService(s)
	s.Leaderboards = NewLeaderboardsService(s)
	s.Metagame = NewMetagameService(s)
	s.Players = NewPlayersService(s)
	s.Pushtokens = NewPushtokensService(s)
	s.QuestMilestones = NewQuestMilestonesService(s)
	s.Quests = NewQuestsService(s)
	s.Revisions = NewRevisionsService(s)
	s.Rooms = NewRoomsService(s)
	s.Scores = NewScoresService(s)
	s.Snapshots = NewSnapshotsService(s)
	s.TurnBasedMatches = NewTurnBasedMatchesService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	AchievementDefinitions *AchievementDefinitionsService

	Achievements *AchievementsService

	Applications *ApplicationsService

	Events *EventsService

	Leaderboards *LeaderboardsService

	Metagame *MetagameService

	Players *PlayersService

	Pushtokens *PushtokensService

	QuestMilestones *QuestMilestonesService

	Quests *QuestsService

	Revisions *RevisionsService

	Rooms *RoomsService

	Scores *ScoresService

	Snapshots *SnapshotsService

	TurnBasedMatches *TurnBasedMatchesService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAchievementDefinitionsService(s *Service) *AchievementDefinitionsService {
	rs := &AchievementDefinitionsService{s: s}
	return rs
}

type AchievementDefinitionsService struct {
	s *Service
}

func NewAchievementsService(s *Service) *AchievementsService {
	rs := &AchievementsService{s: s}
	return rs
}

type AchievementsService struct {
	s *Service
}

func NewApplicationsService(s *Service) *ApplicationsService {
	rs := &ApplicationsService{s: s}
	return rs
}

type ApplicationsService struct {
	s *Service
}

func NewEventsService(s *Service) *EventsService {
	rs := &EventsService{s: s}
	return rs
}

type EventsService struct {
	s *Service
}

func NewLeaderboardsService(s *Service) *LeaderboardsService {
	rs := &LeaderboardsService{s: s}
	return rs
}

type LeaderboardsService struct {
	s *Service
}

func NewMetagameService(s *Service) *MetagameService {
	rs := &MetagameService{s: s}
	return rs
}

type MetagameService struct {
	s *Service
}

func NewPlayersService(s *Service) *PlayersService {
	rs := &PlayersService{s: s}
	return rs
}

type PlayersService struct {
	s *Service
}

func NewPushtokensService(s *Service) *PushtokensService {
	rs := &PushtokensService{s: s}
	return rs
}

type PushtokensService struct {
	s *Service
}

func NewQuestMilestonesService(s *Service) *QuestMilestonesService {
	rs := &QuestMilestonesService{s: s}
	return rs
}

type QuestMilestonesService struct {
	s *Service
}

func NewQuestsService(s *Service) *QuestsService {
	rs := &QuestsService{s: s}
	return rs
}

type QuestsService struct {
	s *Service
}

func NewRevisionsService(s *Service) *RevisionsService {
	rs := &RevisionsService{s: s}
	return rs
}

type RevisionsService struct {
	s *Service
}

func NewRoomsService(s *Service) *RoomsService {
	rs := &RoomsService{s: s}
	return rs
}

type RoomsService struct {
	s *Service
}

func NewScoresService(s *Service) *ScoresService {
	rs := &ScoresService{s: s}
	return rs
}

type ScoresService struct {
	s *Service
}

func NewSnapshotsService(s *Service) *SnapshotsService {
	rs := &SnapshotsService{s: s}
	return rs
}

type SnapshotsService struct {
	s *Service
}

func NewTurnBasedMatchesService(s *Service) *TurnBasedMatchesService {
	rs := &TurnBasedMatchesService{s: s}
	return rs
}

type TurnBasedMatchesService struct {
	s *Service
}

// AchievementDefinition: This is a JSON template for an achievement
// definition object.
type AchievementDefinition struct {
	// AchievementType: The type of the achievement.
	// Possible values are:
	// - "STANDARD" - Achievement is either locked or unlocked.
	// - "INCREMENTAL" - Achievement is incremental.
	AchievementType string `json:"achievementType,omitempty"`

	// Description: The description of the achievement.
	Description string `json:"description,omitempty"`

	// ExperiencePoints: Experience points which will be earned when
	// unlocking this achievement.
	ExperiencePoints int64 `json:"experiencePoints,omitempty,string"`

	// FormattedTotalSteps: The total steps for an incremental achievement
	// as a string.
	FormattedTotalSteps string `json:"formattedTotalSteps,omitempty"`

	// Id: The ID of the achievement.
	Id string `json:"id,omitempty"`

	// InitialState: The initial state of the achievement.
	// Possible values are:
	// - "HIDDEN" - Achievement is hidden.
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	InitialState string `json:"initialState,omitempty"`

	// IsRevealedIconUrlDefault: Indicates whether the revealed icon image
	// being returned is a default image, or is provided by the game.
	IsRevealedIconUrlDefault bool `json:"isRevealedIconUrlDefault,omitempty"`

	// IsUnlockedIconUrlDefault: Indicates whether the unlocked icon image
	// being returned is a default image, or is game-provided.
	IsUnlockedIconUrlDefault bool `json:"isUnlockedIconUrlDefault,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementDefinition.
	Kind string `json:"kind,omitempty"`

	// Name: The name of the achievement.
	Name string `json:"name,omitempty"`

	// RevealedIconUrl: The image URL for the revealed achievement icon.
	RevealedIconUrl string `json:"revealedIconUrl,omitempty"`

	// TotalSteps: The total steps for an incremental achievement.
	TotalSteps int64 `json:"totalSteps,omitempty"`

	// UnlockedIconUrl: The image URL for the unlocked achievement icon.
	UnlockedIconUrl string `json:"unlockedIconUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AchievementType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementDefinition) MarshalJSON() ([]byte, error) {
	type noMethod AchievementDefinition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementDefinitionsListResponse: This is a JSON template for a
// list of achievement definition objects.
type AchievementDefinitionsListResponse struct {
	// Items: The achievement definitions.
	Items []*AchievementDefinition `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementDefinitionsListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *AchievementDefinitionsListResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementDefinitionsListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementIncrementResponse: This is a JSON template for an
// achievement increment response
type AchievementIncrementResponse struct {
	// CurrentSteps: The current steps recorded for this incremental
	// achievement.
	CurrentSteps int64 `json:"currentSteps,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementIncrementResponse.
	Kind string `json:"kind,omitempty"`

	// NewlyUnlocked: Whether the the current steps for the achievement has
	// reached the number of steps required to unlock.
	NewlyUnlocked bool `json:"newlyUnlocked,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CurrentSteps") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementIncrementResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementIncrementResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementRevealResponse: This is a JSON template for an achievement
// reveal response
type AchievementRevealResponse struct {
	// CurrentState: The current state of the achievement for which a reveal
	// was attempted. This might be UNLOCKED if the achievement was already
	// unlocked.
	// Possible values are:
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	CurrentState string `json:"currentState,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementRevealResponse.
	Kind string `json:"kind,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CurrentState") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementRevealResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementRevealResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementSetStepsAtLeastResponse: This is a JSON template for an
// achievement set steps at least response.
type AchievementSetStepsAtLeastResponse struct {
	// CurrentSteps: The current steps recorded for this incremental
	// achievement.
	CurrentSteps int64 `json:"currentSteps,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementSetStepsAtLeastResponse.
	Kind string `json:"kind,omitempty"`

	// NewlyUnlocked: Whether the the current steps for the achievement has
	// reached the number of steps required to unlock.
	NewlyUnlocked bool `json:"newlyUnlocked,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CurrentSteps") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementSetStepsAtLeastResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementSetStepsAtLeastResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementUnlockResponse: This is a JSON template for an achievement
// unlock response
type AchievementUnlockResponse struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementUnlockResponse.
	Kind string `json:"kind,omitempty"`

	// NewlyUnlocked: Whether this achievement was newly unlocked (that is,
	// whether the unlock request for the achievement was the first for the
	// player).
	NewlyUnlocked bool `json:"newlyUnlocked,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementUnlockResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementUnlockResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementUpdateMultipleRequest: This is a JSON template for a list
// of achievement update requests.
type AchievementUpdateMultipleRequest struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementUpdateMultipleRequest.
	Kind string `json:"kind,omitempty"`

	// Updates: The individual achievement update requests.
	Updates []*AchievementUpdateRequest `json:"updates,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementUpdateMultipleRequest) MarshalJSON() ([]byte, error) {
	type noMethod AchievementUpdateMultipleRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementUpdateMultipleResponse: This is a JSON template for an
// achievement unlock response.
type AchievementUpdateMultipleResponse struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementUpdateListResponse.
	Kind string `json:"kind,omitempty"`

	// UpdatedAchievements: The updated state of the achievements.
	UpdatedAchievements []*AchievementUpdateResponse `json:"updatedAchievements,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementUpdateMultipleResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementUpdateMultipleResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementUpdateRequest: This is a JSON template for a request to
// update an achievement.
type AchievementUpdateRequest struct {
	// AchievementId: The achievement this update is being applied to.
	AchievementId string `json:"achievementId,omitempty"`

	// IncrementPayload: The payload if an update of type INCREMENT was
	// requested for the achievement.
	IncrementPayload *GamesAchievementIncrement `json:"incrementPayload,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementUpdateRequest.
	Kind string `json:"kind,omitempty"`

	// SetStepsAtLeastPayload: The payload if an update of type
	// SET_STEPS_AT_LEAST was requested for the achievement.
	SetStepsAtLeastPayload *GamesAchievementSetStepsAtLeast `json:"setStepsAtLeastPayload,omitempty"`

	// UpdateType: The type of update being applied.
	// Possible values are:
	// - "REVEAL" - Achievement is revealed.
	// - "UNLOCK" - Achievement is unlocked.
	// - "INCREMENT" - Achievement is incremented.
	// - "SET_STEPS_AT_LEAST" - Achievement progress is set to at least the
	// passed value.
	UpdateType string `json:"updateType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AchievementId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementUpdateRequest) MarshalJSON() ([]byte, error) {
	type noMethod AchievementUpdateRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementUpdateResponse: This is a JSON template for an achievement
// update response.
type AchievementUpdateResponse struct {
	// AchievementId: The achievement this update is was applied to.
	AchievementId string `json:"achievementId,omitempty"`

	// CurrentState: The current state of the achievement.
	// Possible values are:
	// - "HIDDEN" - Achievement is hidden.
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	CurrentState string `json:"currentState,omitempty"`

	// CurrentSteps: The current steps recorded for this achievement if it
	// is incremental.
	CurrentSteps int64 `json:"currentSteps,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementUpdateResponse.
	Kind string `json:"kind,omitempty"`

	// NewlyUnlocked: Whether this achievement was newly unlocked (that is,
	// whether the unlock request for the achievement was the first for the
	// player).
	NewlyUnlocked bool `json:"newlyUnlocked,omitempty"`

	// UpdateOccurred: Whether the requested updates actually affected the
	// achievement.
	UpdateOccurred bool `json:"updateOccurred,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AchievementId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementUpdateResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementUpdateResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AggregateStats: This is a JSON template for aggregate stats.
type AggregateStats struct {
	// Count: The number of messages sent between a pair of peers.
	Count int64 `json:"count,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#aggregateStats.
	Kind string `json:"kind,omitempty"`

	// Max: The maximum amount.
	Max int64 `json:"max,omitempty,string"`

	// Min: The minimum amount.
	Min int64 `json:"min,omitempty,string"`

	// Sum: The total number of bytes sent for messages between a pair of
	// peers.
	Sum int64 `json:"sum,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "Count") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AggregateStats) MarshalJSON() ([]byte, error) {
	type noMethod AggregateStats
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AnonymousPlayer: This is a JSON template for an anonymous player
type AnonymousPlayer struct {
	// AvatarImageUrl: The base URL for the image to display for the
	// anonymous player.
	AvatarImageUrl string `json:"avatarImageUrl,omitempty"`

	// DisplayName: The name to display for the anonymous player.
	DisplayName string `json:"displayName,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#anonymousPlayer.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AvatarImageUrl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AnonymousPlayer) MarshalJSON() ([]byte, error) {
	type noMethod AnonymousPlayer
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Application: This is a JSON template for the Application resource.
type Application struct {
	// AchievementCount: The number of achievements visible to the currently
	// authenticated player.
	AchievementCount int64 `json:"achievement_count,omitempty"`

	// Assets: The assets of the application.
	Assets []*ImageAsset `json:"assets,omitempty"`

	// Author: The author of the application.
	Author string `json:"author,omitempty"`

	// Category: The category of the application.
	Category *ApplicationCategory `json:"category,omitempty"`

	// Description: The description of the application.
	Description string `json:"description,omitempty"`

	// EnabledFeatures: A list of features that have been enabled for the
	// application.
	// Possible values are:
	// - "SNAPSHOTS" - Snapshots has been enabled
	EnabledFeatures []string `json:"enabledFeatures,omitempty"`

	// Id: The ID of the application.
	Id string `json:"id,omitempty"`

	// Instances: The instances of the application.
	Instances []*Instance `json:"instances,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#application.
	Kind string `json:"kind,omitempty"`

	// LastUpdatedTimestamp: The last updated timestamp of the application.
	LastUpdatedTimestamp int64 `json:"lastUpdatedTimestamp,omitempty,string"`

	// LeaderboardCount: The number of leaderboards visible to the currently
	// authenticated player.
	LeaderboardCount int64 `json:"leaderboard_count,omitempty"`

	// Name: The name of the application.
	Name string `json:"name,omitempty"`

	// ThemeColor: A hint to the client UI for what color to use as an
	// app-themed color. The color is given as an RGB triplet (e.g.
	// "E0E0E0").
	ThemeColor string `json:"themeColor,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AchievementCount") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Application) MarshalJSON() ([]byte, error) {
	type noMethod Application
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ApplicationCategory: This is a JSON template for an application
// category object.
type ApplicationCategory struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#applicationCategory.
	Kind string `json:"kind,omitempty"`

	// Primary: The primary category.
	Primary string `json:"primary,omitempty"`

	// Secondary: The secondary category.
	Secondary string `json:"secondary,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ApplicationCategory) MarshalJSON() ([]byte, error) {
	type noMethod ApplicationCategory
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Category: This is a JSON template for data related to individual game
// categories.
type Category struct {
	// Category: The category name.
	Category string `json:"category,omitempty"`

	// ExperiencePoints: Experience points earned in this category.
	ExperiencePoints int64 `json:"experiencePoints,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#category.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Category") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Category) MarshalJSON() ([]byte, error) {
	type noMethod Category
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CategoryListResponse: This is a JSON template for a list of category
// data objects.
type CategoryListResponse struct {
	// Items: The list of categories with usage data.
	Items []*Category `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#categoryListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *CategoryListResponse) MarshalJSON() ([]byte, error) {
	type noMethod CategoryListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventBatchRecordFailure: This is a JSON template for a batch update
// failure resource.
type EventBatchRecordFailure struct {
	// FailureCause: The cause for the update failure.
	// Possible values are:
	// - "TOO_LARGE": A batch request was issued with more events than are
	// allowed in a single batch.
	// - "TIME_PERIOD_EXPIRED": A batch was sent with data too far in the
	// past to record.
	// - "TIME_PERIOD_SHORT": A batch was sent with a time range that was
	// too short.
	// - "TIME_PERIOD_LONG": A batch was sent with a time range that was too
	// long.
	// - "ALREADY_UPDATED": An attempt was made to record a batch of data
	// which was already seen.
	// - "RECORD_RATE_HIGH": An attempt was made to record data faster than
	// the server will apply updates.
	FailureCause string `json:"failureCause,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventBatchRecordFailure.
	Kind string `json:"kind,omitempty"`

	// Range: The time range which was rejected; empty for a request-wide
	// failure.
	Range *EventPeriodRange `json:"range,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FailureCause") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventBatchRecordFailure) MarshalJSON() ([]byte, error) {
	type noMethod EventBatchRecordFailure
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventChild: This is a JSON template for an event child relationship
// resource.
type EventChild struct {
	// ChildId: The ID of the child event.
	ChildId string `json:"childId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventChild.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChildId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventChild) MarshalJSON() ([]byte, error) {
	type noMethod EventChild
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventDefinition: This is a JSON template for an event definition
// resource.
type EventDefinition struct {
	// ChildEvents: A list of events that are a child of this event.
	ChildEvents []*EventChild `json:"childEvents,omitempty"`

	// Description: Description of what this event represents.
	Description string `json:"description,omitempty"`

	// DisplayName: The name to display for the event.
	DisplayName string `json:"displayName,omitempty"`

	// Id: The ID of the event.
	Id string `json:"id,omitempty"`

	// ImageUrl: The base URL for the image that represents the event.
	ImageUrl string `json:"imageUrl,omitempty"`

	// IsDefaultImageUrl: Indicates whether the icon image being returned is
	// a default image, or is game-provided.
	IsDefaultImageUrl bool `json:"isDefaultImageUrl,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventDefinition.
	Kind string `json:"kind,omitempty"`

	// Visibility: The visibility of event being tracked in this
	// definition.
	// Possible values are:
	// - "REVEALED": This event should be visible to all users.
	// - "HIDDEN": This event should only be shown to users that have
	// recorded this event at least once.
	Visibility string `json:"visibility,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChildEvents") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventDefinition) MarshalJSON() ([]byte, error) {
	type noMethod EventDefinition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventDefinitionListResponse: This is a JSON template for a
// ListDefinitions response.
type EventDefinitionListResponse struct {
	// Items: The event definitions.
	Items []*EventDefinition `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventDefinitionListResponse.
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

func (s *EventDefinitionListResponse) MarshalJSON() ([]byte, error) {
	type noMethod EventDefinitionListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventPeriodRange: This is a JSON template for an event period time
// range.
type EventPeriodRange struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventPeriodRange.
	Kind string `json:"kind,omitempty"`

	// PeriodEndMillis: The time when this update period ends, in millis,
	// since 1970 UTC (Unix Epoch).
	PeriodEndMillis int64 `json:"periodEndMillis,omitempty,string"`

	// PeriodStartMillis: The time when this update period begins, in
	// millis, since 1970 UTC (Unix Epoch).
	PeriodStartMillis int64 `json:"periodStartMillis,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventPeriodRange) MarshalJSON() ([]byte, error) {
	type noMethod EventPeriodRange
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventPeriodUpdate: This is a JSON template for an event period update
// resource.
type EventPeriodUpdate struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventPeriodUpdate.
	Kind string `json:"kind,omitempty"`

	// TimePeriod: The time period being covered by this update.
	TimePeriod *EventPeriodRange `json:"timePeriod,omitempty"`

	// Updates: The updates being made for this time period.
	Updates []*EventUpdateRequest `json:"updates,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventPeriodUpdate) MarshalJSON() ([]byte, error) {
	type noMethod EventPeriodUpdate
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventRecordFailure: This is a JSON template for an event update
// failure resource.
type EventRecordFailure struct {
	// EventId: The ID of the event that was not updated.
	EventId string `json:"eventId,omitempty"`

	// FailureCause: The cause for the update failure.
	// Possible values are:
	// - "NOT_FOUND" - An attempt was made to set an event that was not
	// defined.
	// - "INVALID_UPDATE_VALUE" - An attempt was made to increment an event
	// by a non-positive value.
	FailureCause string `json:"failureCause,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventRecordFailure.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EventId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventRecordFailure) MarshalJSON() ([]byte, error) {
	type noMethod EventRecordFailure
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventRecordRequest: This is a JSON template for an event period
// update resource.
type EventRecordRequest struct {
	// CurrentTimeMillis: The current time when this update was sent, in
	// milliseconds, since 1970 UTC (Unix Epoch).
	CurrentTimeMillis int64 `json:"currentTimeMillis,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventRecordRequest.
	Kind string `json:"kind,omitempty"`

	// RequestId: The request ID used to identify this attempt to record
	// events.
	RequestId int64 `json:"requestId,omitempty,string"`

	// TimePeriods: A list of the time period updates being made in this
	// request.
	TimePeriods []*EventPeriodUpdate `json:"timePeriods,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CurrentTimeMillis")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventRecordRequest) MarshalJSON() ([]byte, error) {
	type noMethod EventRecordRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventUpdateRequest: This is a JSON template for an event period
// update resource.
type EventUpdateRequest struct {
	// DefinitionId: The ID of the event being modified in this update.
	DefinitionId string `json:"definitionId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventUpdateRequest.
	Kind string `json:"kind,omitempty"`

	// UpdateCount: The number of times this event occurred in this time
	// period.
	UpdateCount int64 `json:"updateCount,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "DefinitionId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventUpdateRequest) MarshalJSON() ([]byte, error) {
	type noMethod EventUpdateRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventUpdateResponse: This is a JSON template for an event period
// update resource.
type EventUpdateResponse struct {
	// BatchFailures: Any batch-wide failures which occurred applying
	// updates.
	BatchFailures []*EventBatchRecordFailure `json:"batchFailures,omitempty"`

	// EventFailures: Any failures updating a particular event.
	EventFailures []*EventRecordFailure `json:"eventFailures,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#eventUpdateResponse.
	Kind string `json:"kind,omitempty"`

	// PlayerEvents: The current status of any updated events
	PlayerEvents []*PlayerEvent `json:"playerEvents,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "BatchFailures") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventUpdateResponse) MarshalJSON() ([]byte, error) {
	type noMethod EventUpdateResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesAchievementIncrement: This is a JSON template for the payload to
// request to increment an achievement.
type GamesAchievementIncrement struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#GamesAchievementIncrement.
	Kind string `json:"kind,omitempty"`

	// RequestId: The requestId associated with an increment to an
	// achievement.
	RequestId int64 `json:"requestId,omitempty,string"`

	// Steps: The number of steps to be incremented.
	Steps int64 `json:"steps,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesAchievementIncrement) MarshalJSON() ([]byte, error) {
	type noMethod GamesAchievementIncrement
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesAchievementSetStepsAtLeast: This is a JSON template for the
// payload to request to increment an achievement.
type GamesAchievementSetStepsAtLeast struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#GamesAchievementSetStepsAtLeast.
	Kind string `json:"kind,omitempty"`

	// Steps: The minimum number of steps for the achievement to be set to.
	Steps int64 `json:"steps,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesAchievementSetStepsAtLeast) MarshalJSON() ([]byte, error) {
	type noMethod GamesAchievementSetStepsAtLeast
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImageAsset: This is a JSON template for an image asset object.
type ImageAsset struct {
	// Height: The height of the asset.
	Height int64 `json:"height,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#imageAsset.
	Kind string `json:"kind,omitempty"`

	// Name: The name of the asset.
	Name string `json:"name,omitempty"`

	// Url: The URL of the asset.
	Url string `json:"url,omitempty"`

	// Width: The width of the asset.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImageAsset) MarshalJSON() ([]byte, error) {
	type noMethod ImageAsset
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Instance: This is a JSON template for the Instance resource.
type Instance struct {
	// AcquisitionUri: URI which shows where a user can acquire this
	// instance.
	AcquisitionUri string `json:"acquisitionUri,omitempty"`

	// AndroidInstance: Platform dependent details for Android.
	AndroidInstance *InstanceAndroidDetails `json:"androidInstance,omitempty"`

	// IosInstance: Platform dependent details for iOS.
	IosInstance *InstanceIosDetails `json:"iosInstance,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#instance.
	Kind string `json:"kind,omitempty"`

	// Name: Localized display name.
	Name string `json:"name,omitempty"`

	// PlatformType: The platform type.
	// Possible values are:
	// - "ANDROID" - Instance is for Android.
	// - "IOS" - Instance is for iOS
	// - "WEB_APP" - Instance is for Web App.
	PlatformType string `json:"platformType,omitempty"`

	// RealtimePlay: Flag to show if this game instance supports realtime
	// play.
	RealtimePlay bool `json:"realtimePlay,omitempty"`

	// TurnBasedPlay: Flag to show if this game instance supports turn based
	// play.
	TurnBasedPlay bool `json:"turnBasedPlay,omitempty"`

	// WebInstance: Platform dependent details for Web.
	WebInstance *InstanceWebDetails `json:"webInstance,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AcquisitionUri") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Instance) MarshalJSON() ([]byte, error) {
	type noMethod Instance
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InstanceAndroidDetails: This is a JSON template for the Android
// instance details resource.
type InstanceAndroidDetails struct {
	// EnablePiracyCheck: Flag indicating whether the anti-piracy check is
	// enabled.
	EnablePiracyCheck bool `json:"enablePiracyCheck,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#instanceAndroidDetails.
	Kind string `json:"kind,omitempty"`

	// PackageName: Android package name which maps to Google Play URL.
	PackageName string `json:"packageName,omitempty"`

	// Preferred: Indicates that this instance is the default for new
	// installations.
	Preferred bool `json:"preferred,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EnablePiracyCheck")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InstanceAndroidDetails) MarshalJSON() ([]byte, error) {
	type noMethod InstanceAndroidDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InstanceIosDetails: This is a JSON template for the iOS details
// resource.
type InstanceIosDetails struct {
	// BundleIdentifier: Bundle identifier.
	BundleIdentifier string `json:"bundleIdentifier,omitempty"`

	// ItunesAppId: iTunes App ID.
	ItunesAppId string `json:"itunesAppId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#instanceIosDetails.
	Kind string `json:"kind,omitempty"`

	// PreferredForIpad: Indicates that this instance is the default for new
	// installations on iPad devices.
	PreferredForIpad bool `json:"preferredForIpad,omitempty"`

	// PreferredForIphone: Indicates that this instance is the default for
	// new installations on iPhone devices.
	PreferredForIphone bool `json:"preferredForIphone,omitempty"`

	// SupportIpad: Flag to indicate if this instance supports iPad.
	SupportIpad bool `json:"supportIpad,omitempty"`

	// SupportIphone: Flag to indicate if this instance supports iPhone.
	SupportIphone bool `json:"supportIphone,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BundleIdentifier") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InstanceIosDetails) MarshalJSON() ([]byte, error) {
	type noMethod InstanceIosDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InstanceWebDetails: This is a JSON template for the Web details
// resource.
type InstanceWebDetails struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#instanceWebDetails.
	Kind string `json:"kind,omitempty"`

	// LaunchUrl: Launch URL for the game.
	LaunchUrl string `json:"launchUrl,omitempty"`

	// Preferred: Indicates that this instance is the default for new
	// installations.
	Preferred bool `json:"preferred,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InstanceWebDetails) MarshalJSON() ([]byte, error) {
	type noMethod InstanceWebDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Leaderboard: This is a JSON template for the Leaderboard resource.
type Leaderboard struct {
	// IconUrl: The icon for the leaderboard.
	IconUrl string `json:"iconUrl,omitempty"`

	// Id: The leaderboard ID.
	Id string `json:"id,omitempty"`

	// IsIconUrlDefault: Indicates whether the icon image being returned is
	// a default image, or is game-provided.
	IsIconUrlDefault bool `json:"isIconUrlDefault,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboard.
	Kind string `json:"kind,omitempty"`

	// Name: The name of the leaderboard.
	Name string `json:"name,omitempty"`

	// Order: How scores are ordered.
	// Possible values are:
	// - "LARGER_IS_BETTER" - Larger values are better; scores are sorted in
	// descending order.
	// - "SMALLER_IS_BETTER" - Smaller values are better; scores are sorted
	// in ascending order.
	Order string `json:"order,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "IconUrl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Leaderboard) MarshalJSON() ([]byte, error) {
	type noMethod Leaderboard
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardEntry: This is a JSON template for the Leaderboard Entry
// resource.
type LeaderboardEntry struct {
	// FormattedScore: The localized string for the numerical value of this
	// score.
	FormattedScore string `json:"formattedScore,omitempty"`

	// FormattedScoreRank: The localized string for the rank of this score
	// for this leaderboard.
	FormattedScoreRank string `json:"formattedScoreRank,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboardEntry.
	Kind string `json:"kind,omitempty"`

	// Player: The player who holds this score.
	Player *Player `json:"player,omitempty"`

	// ScoreRank: The rank of this score for this leaderboard.
	ScoreRank int64 `json:"scoreRank,omitempty,string"`

	// ScoreTag: Additional information about the score. Values must contain
	// no more than 64 URI-safe characters as defined by section 2.3 of RFC
	// 3986.
	ScoreTag string `json:"scoreTag,omitempty"`

	// ScoreValue: The numerical value of this score.
	ScoreValue int64 `json:"scoreValue,omitempty,string"`

	// TimeSpan: The time span of this high score.
	// Possible values are:
	// - "ALL_TIME" - The score is an all-time high score.
	// - "WEEKLY" - The score is a weekly high score.
	// - "DAILY" - The score is a daily high score.
	TimeSpan string `json:"timeSpan,omitempty"`

	// WriteTimestampMillis: The timestamp at which this score was recorded,
	// in milliseconds since the epoch in UTC.
	WriteTimestampMillis int64 `json:"writeTimestampMillis,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "FormattedScore") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LeaderboardEntry) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardEntry
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardListResponse: This is a JSON template for a list of
// leaderboard objects.
type LeaderboardListResponse struct {
	// Items: The leaderboards.
	Items []*Leaderboard `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboardListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *LeaderboardListResponse) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardScoreRank: This is a JSON template for a score rank in a
// leaderboard.
type LeaderboardScoreRank struct {
	// FormattedNumScores: The number of scores in the leaderboard as a
	// string.
	FormattedNumScores string `json:"formattedNumScores,omitempty"`

	// FormattedRank: The rank in the leaderboard as a string.
	FormattedRank string `json:"formattedRank,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboardScoreRank.
	Kind string `json:"kind,omitempty"`

	// NumScores: The number of scores in the leaderboard.
	NumScores int64 `json:"numScores,omitempty,string"`

	// Rank: The rank in the leaderboard.
	Rank int64 `json:"rank,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "FormattedNumScores")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LeaderboardScoreRank) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardScoreRank
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardScores: This is a JSON template for a ListScores response.
type LeaderboardScores struct {
	// Items: The scores in the leaderboard.
	Items []*LeaderboardEntry `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboardScores.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The pagination token for the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// NumScores: The total number of scores in the leaderboard.
	NumScores int64 `json:"numScores,omitempty,string"`

	// PlayerScore: The score of the requesting player on the leaderboard.
	// The player's score may appear both here and in the list of scores
	// above. If you are viewing a public leaderboard and the player is not
	// sharing their gameplay information publicly, the scoreRank and
	// formattedScoreRank values will not be present.
	PlayerScore *LeaderboardEntry `json:"playerScore,omitempty"`

	// PrevPageToken: The pagination token for the previous page of results.
	PrevPageToken string `json:"prevPageToken,omitempty"`

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

func (s *LeaderboardScores) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardScores
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// MetagameConfig: This is a JSON template for the metagame config
// resource
type MetagameConfig struct {
	// CurrentVersion: Current version of the metagame configuration data.
	// When this data is updated, the version number will be increased by
	// one.
	CurrentVersion int64 `json:"currentVersion,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#metagameConfig.
	Kind string `json:"kind,omitempty"`

	// PlayerLevels: The list of player levels.
	PlayerLevels []*PlayerLevel `json:"playerLevels,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CurrentVersion") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MetagameConfig) MarshalJSON() ([]byte, error) {
	type noMethod MetagameConfig
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// NetworkDiagnostics: This is a JSON template for network diagnostics
// reported for a client.
type NetworkDiagnostics struct {
	// AndroidNetworkSubtype: The Android network subtype.
	AndroidNetworkSubtype int64 `json:"androidNetworkSubtype,omitempty"`

	// AndroidNetworkType: The Android network type.
	AndroidNetworkType int64 `json:"androidNetworkType,omitempty"`

	// IosNetworkType: iOS network type as defined in Reachability.h.
	IosNetworkType int64 `json:"iosNetworkType,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#networkDiagnostics.
	Kind string `json:"kind,omitempty"`

	// NetworkOperatorCode: The MCC+MNC code for the client's network
	// connection. On Android:
	// http://developer.android.com/reference/android/telephony/TelephonyManager.html#getNetworkOperator() On iOS, see:
	// https://developer.apple.com/library/ios/documentation/NetworkingInternet/Reference/CTCarrier/Reference/Reference.html
	NetworkOperatorCode string `json:"networkOperatorCode,omitempty"`

	// NetworkOperatorName: The name of the carrier of the client's network
	// connection. On Android:
	// http://developer.android.com/reference/android/telephony/TelephonyManager.html#getNetworkOperatorName() On iOS:
	// https://developer.apple.com/library/ios/documentation/NetworkingInternet/Reference/CTCarrier/Reference/Reference.html#//apple_ref/occ/instp/CTCarrier/carrierName
	NetworkOperatorName string `json:"networkOperatorName,omitempty"`

	// RegistrationLatencyMillis: The amount of time in milliseconds it took
	// for the client to establish a connection with the XMPP server.
	RegistrationLatencyMillis int64 `json:"registrationLatencyMillis,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "AndroidNetworkSubtype") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *NetworkDiagnostics) MarshalJSON() ([]byte, error) {
	type noMethod NetworkDiagnostics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ParticipantResult: This is a JSON template for a result for a match
// participant.
type ParticipantResult struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#participantResult.
	Kind string `json:"kind,omitempty"`

	// ParticipantId: The ID of the participant.
	ParticipantId string `json:"participantId,omitempty"`

	// Placing: The placement or ranking of the participant in the match
	// results; a number from one to the number of participants in the
	// match. Multiple participants may have the same placing value in case
	// of a type.
	Placing int64 `json:"placing,omitempty"`

	// Result: The result of the participant for this match.
	// Possible values are:
	// - "MATCH_RESULT_WIN" - The participant won the match.
	// - "MATCH_RESULT_LOSS" - The participant lost the match.
	// - "MATCH_RESULT_TIE" - The participant tied the match.
	// - "MATCH_RESULT_NONE" - There was no winner for the match (nobody
	// wins or loses this kind of game.)
	// - "MATCH_RESULT_DISCONNECT" - The participant disconnected / left
	// during the match.
	// - "MATCH_RESULT_DISAGREED" - Different clients reported different
	// results for this participant.
	Result string `json:"result,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ParticipantResult) MarshalJSON() ([]byte, error) {
	type noMethod ParticipantResult
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PeerChannelDiagnostics: This is a JSON template for peer channel
// diagnostics.
type PeerChannelDiagnostics struct {
	// BytesReceived: Number of bytes received.
	BytesReceived *AggregateStats `json:"bytesReceived,omitempty"`

	// BytesSent: Number of bytes sent.
	BytesSent *AggregateStats `json:"bytesSent,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#peerChannelDiagnostics.
	Kind string `json:"kind,omitempty"`

	// NumMessagesLost: Number of messages lost.
	NumMessagesLost int64 `json:"numMessagesLost,omitempty"`

	// NumMessagesReceived: Number of messages received.
	NumMessagesReceived int64 `json:"numMessagesReceived,omitempty"`

	// NumMessagesSent: Number of messages sent.
	NumMessagesSent int64 `json:"numMessagesSent,omitempty"`

	// NumSendFailures: Number of send failures.
	NumSendFailures int64 `json:"numSendFailures,omitempty"`

	// RoundtripLatencyMillis: Roundtrip latency stats in milliseconds.
	RoundtripLatencyMillis *AggregateStats `json:"roundtripLatencyMillis,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BytesReceived") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PeerChannelDiagnostics) MarshalJSON() ([]byte, error) {
	type noMethod PeerChannelDiagnostics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PeerSessionDiagnostics: This is a JSON template for peer session
// diagnostics.
type PeerSessionDiagnostics struct {
	// ConnectedTimestampMillis: Connected time in milliseconds.
	ConnectedTimestampMillis int64 `json:"connectedTimestampMillis,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#peerSessionDiagnostics.
	Kind string `json:"kind,omitempty"`

	// ParticipantId: The participant ID of the peer.
	ParticipantId string `json:"participantId,omitempty"`

	// ReliableChannel: Reliable channel diagnostics.
	ReliableChannel *PeerChannelDiagnostics `json:"reliableChannel,omitempty"`

	// UnreliableChannel: Unreliable channel diagnostics.
	UnreliableChannel *PeerChannelDiagnostics `json:"unreliableChannel,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ConnectedTimestampMillis") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PeerSessionDiagnostics) MarshalJSON() ([]byte, error) {
	type noMethod PeerSessionDiagnostics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Played: This is a JSON template for metadata about a player playing a
// game with the currently authenticated user.
type Played struct {
	// AutoMatched: True if the player was auto-matched with the currently
	// authenticated user.
	AutoMatched bool `json:"autoMatched,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#played.
	Kind string `json:"kind,omitempty"`

	// TimeMillis: The last time the player played the game in milliseconds
	// since the epoch in UTC.
	TimeMillis int64 `json:"timeMillis,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "AutoMatched") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Played) MarshalJSON() ([]byte, error) {
	type noMethod Played
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Player: This is a JSON template for a Player resource.
type Player struct {
	// AvatarImageUrl: The base URL for the image that represents the
	// player.
	AvatarImageUrl string `json:"avatarImageUrl,omitempty"`

	// DisplayName: The name to display for the player.
	DisplayName string `json:"displayName,omitempty"`

	// ExperienceInfo: An object to represent Play Game experience
	// information for the player.
	ExperienceInfo *PlayerExperienceInfo `json:"experienceInfo,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#player.
	Kind string `json:"kind,omitempty"`

	// LastPlayedWith: Details about the last time this player played a
	// multiplayer game with the currently authenticated player. Populated
	// for PLAYED_WITH player collection members.
	LastPlayedWith *Played `json:"lastPlayedWith,omitempty"`

	// Name: An object representation of the individual components of the
	// player's name. For some players, these fields may not be present.
	Name *PlayerName `json:"name,omitempty"`

	// PlayerId: The ID of the player.
	PlayerId string `json:"playerId,omitempty"`

	// Title: The player's title rewarded for their game activities.
	Title string `json:"title,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AvatarImageUrl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Player) MarshalJSON() ([]byte, error) {
	type noMethod Player
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerName: An object representation of the individual components of
// the player's name. For some players, these fields may not be present.
type PlayerName struct {
	// FamilyName: The family name of this player. In some places, this is
	// known as the last name.
	FamilyName string `json:"familyName,omitempty"`

	// GivenName: The given name of this player. In some places, this is
	// known as the first name.
	GivenName string `json:"givenName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FamilyName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerName) MarshalJSON() ([]byte, error) {
	type noMethod PlayerName
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerAchievement: This is a JSON template for an achievement object.
type PlayerAchievement struct {
	// AchievementState: The state of the achievement.
	// Possible values are:
	// - "HIDDEN" - Achievement is hidden.
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	AchievementState string `json:"achievementState,omitempty"`

	// CurrentSteps: The current steps for an incremental achievement.
	CurrentSteps int64 `json:"currentSteps,omitempty"`

	// ExperiencePoints: Experience points earned for the achievement. This
	// field is absent for achievements that have not yet been unlocked and
	// 0 for achievements that have been unlocked by testers but that are
	// unpublished.
	ExperiencePoints int64 `json:"experiencePoints,omitempty,string"`

	// FormattedCurrentStepsString: The current steps for an incremental
	// achievement as a string.
	FormattedCurrentStepsString string `json:"formattedCurrentStepsString,omitempty"`

	// Id: The ID of the achievement.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerAchievement.
	Kind string `json:"kind,omitempty"`

	// LastUpdatedTimestamp: The timestamp of the last modification to this
	// achievement's state.
	LastUpdatedTimestamp int64 `json:"lastUpdatedTimestamp,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "AchievementState") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerAchievement) MarshalJSON() ([]byte, error) {
	type noMethod PlayerAchievement
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerAchievementListResponse: This is a JSON template for a list of
// achievement objects.
type PlayerAchievementListResponse struct {
	// Items: The achievements.
	Items []*PlayerAchievement `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerAchievementListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *PlayerAchievementListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerAchievementListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerEvent: This is a JSON template for an event status resource.
type PlayerEvent struct {
	// DefinitionId: The ID of the event definition.
	DefinitionId string `json:"definitionId,omitempty"`

	// FormattedNumEvents: The current number of times this event has
	// occurred, as a string. The formatting of this string depends on the
	// configuration of your event in the Play Games Developer Console.
	FormattedNumEvents string `json:"formattedNumEvents,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerEvent.
	Kind string `json:"kind,omitempty"`

	// NumEvents: The current number of times this event has occurred.
	NumEvents int64 `json:"numEvents,omitempty,string"`

	// PlayerId: The ID of the player.
	PlayerId string `json:"playerId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DefinitionId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerEvent) MarshalJSON() ([]byte, error) {
	type noMethod PlayerEvent
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerEventListResponse: This is a JSON template for a ListByPlayer
// response.
type PlayerEventListResponse struct {
	// Items: The player events.
	Items []*PlayerEvent `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerEventListResponse.
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

func (s *PlayerEventListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerEventListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerExperienceInfo: This is a JSON template for 1P/3P metadata
// about the player's experience.
type PlayerExperienceInfo struct {
	// CurrentExperiencePoints: The current number of experience points for
	// the player.
	CurrentExperiencePoints int64 `json:"currentExperiencePoints,omitempty,string"`

	// CurrentLevel: The current level of the player.
	CurrentLevel *PlayerLevel `json:"currentLevel,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerExperienceInfo.
	Kind string `json:"kind,omitempty"`

	// LastLevelUpTimestampMillis: The timestamp when the player was leveled
	// up, in millis since Unix epoch UTC.
	LastLevelUpTimestampMillis int64 `json:"lastLevelUpTimestampMillis,omitempty,string"`

	// NextLevel: The next level of the player. If the current level is the
	// maximum level, this should be same as the current level.
	NextLevel *PlayerLevel `json:"nextLevel,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CurrentExperiencePoints") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerExperienceInfo) MarshalJSON() ([]byte, error) {
	type noMethod PlayerExperienceInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerLeaderboardScore: This is a JSON template for a player
// leaderboard score object.
type PlayerLeaderboardScore struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerLeaderboardScore.
	Kind string `json:"kind,omitempty"`

	// LeaderboardId: The ID of the leaderboard this score is in.
	LeaderboardId string `json:"leaderboard_id,omitempty"`

	// PublicRank: The public rank of the score in this leaderboard. This
	// object will not be present if the user is not sharing their scores
	// publicly.
	PublicRank *LeaderboardScoreRank `json:"publicRank,omitempty"`

	// ScoreString: The formatted value of this score.
	ScoreString string `json:"scoreString,omitempty"`

	// ScoreTag: Additional information about the score. Values must contain
	// no more than 64 URI-safe characters as defined by section 2.3 of RFC
	// 3986.
	ScoreTag string `json:"scoreTag,omitempty"`

	// ScoreValue: The numerical value of this score.
	ScoreValue int64 `json:"scoreValue,omitempty,string"`

	// SocialRank: The social rank of the score in this leaderboard.
	SocialRank *LeaderboardScoreRank `json:"socialRank,omitempty"`

	// TimeSpan: The time span of this score.
	// Possible values are:
	// - "ALL_TIME" - The score is an all-time score.
	// - "WEEKLY" - The score is a weekly score.
	// - "DAILY" - The score is a daily score.
	TimeSpan string `json:"timeSpan,omitempty"`

	// WriteTimestamp: The timestamp at which this score was recorded, in
	// milliseconds since the epoch in UTC.
	WriteTimestamp int64 `json:"writeTimestamp,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerLeaderboardScore) MarshalJSON() ([]byte, error) {
	type noMethod PlayerLeaderboardScore
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerLeaderboardScoreListResponse: This is a JSON template for a
// list of player leaderboard scores.
type PlayerLeaderboardScoreListResponse struct {
	// Items: The leaderboard scores.
	Items []*PlayerLeaderboardScore `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerLeaderboardScoreListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The pagination token for the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Player: The Player resources for the owner of this score.
	Player *Player `json:"player,omitempty"`

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

func (s *PlayerLeaderboardScoreListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerLeaderboardScoreListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerLevel: This is a JSON template for 1P/3P metadata about a
// user's level.
type PlayerLevel struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerLevel.
	Kind string `json:"kind,omitempty"`

	// Level: The level for the user.
	Level int64 `json:"level,omitempty"`

	// MaxExperiencePoints: The maximum experience points for this level.
	MaxExperiencePoints int64 `json:"maxExperiencePoints,omitempty,string"`

	// MinExperiencePoints: The minimum experience points for this level.
	MinExperiencePoints int64 `json:"minExperiencePoints,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerLevel) MarshalJSON() ([]byte, error) {
	type noMethod PlayerLevel
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerListResponse: This is a JSON template for a third party player
// list response.
type PlayerListResponse struct {
	// Items: The players.
	Items []*Player `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *PlayerListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerScore: This is a JSON template for a player score.
type PlayerScore struct {
	// FormattedScore: The formatted score for this player score.
	FormattedScore string `json:"formattedScore,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerScore.
	Kind string `json:"kind,omitempty"`

	// Score: The numerical value for this player score.
	Score int64 `json:"score,omitempty,string"`

	// ScoreTag: Additional information about this score. Values will
	// contain no more than 64 URI-safe characters as defined by section 2.3
	// of RFC 3986.
	ScoreTag string `json:"scoreTag,omitempty"`

	// TimeSpan: The time span for this player score.
	// Possible values are:
	// - "ALL_TIME" - The score is an all-time score.
	// - "WEEKLY" - The score is a weekly score.
	// - "DAILY" - The score is a daily score.
	TimeSpan string `json:"timeSpan,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FormattedScore") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerScore) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScore
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerScoreListResponse: This is a JSON template for a list of score
// submission statuses.
type PlayerScoreListResponse struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerScoreListResponse.
	Kind string `json:"kind,omitempty"`

	// SubmittedScores: The score submissions statuses.
	SubmittedScores []*PlayerScoreResponse `json:"submittedScores,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerScoreListResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScoreListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerScoreResponse: This is a JSON template for a list of
// leaderboard entry resources.
type PlayerScoreResponse struct {
	// BeatenScoreTimeSpans: The time spans where the submitted score is
	// better than the existing score for that time span.
	// Possible values are:
	// - "ALL_TIME" - The score is an all-time score.
	// - "WEEKLY" - The score is a weekly score.
	// - "DAILY" - The score is a daily score.
	BeatenScoreTimeSpans []string `json:"beatenScoreTimeSpans,omitempty"`

	// FormattedScore: The formatted value of the submitted score.
	FormattedScore string `json:"formattedScore,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerScoreResponse.
	Kind string `json:"kind,omitempty"`

	// LeaderboardId: The leaderboard ID that this score was submitted to.
	LeaderboardId string `json:"leaderboardId,omitempty"`

	// ScoreTag: Additional information about this score. Values will
	// contain no more than 64 URI-safe characters as defined by section 2.3
	// of RFC 3986.
	ScoreTag string `json:"scoreTag,omitempty"`

	// UnbeatenScores: The scores in time spans that have not been beaten.
	// As an example, the submitted score may be better than the player's
	// DAILY score, but not better than the player's scores for the WEEKLY
	// or ALL_TIME time spans.
	UnbeatenScores []*PlayerScore `json:"unbeatenScores,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g.
	// "BeatenScoreTimeSpans") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerScoreResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScoreResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerScoreSubmissionList: This is a JSON template for a list of
// score submission requests
type PlayerScoreSubmissionList struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#playerScoreSubmissionList.
	Kind string `json:"kind,omitempty"`

	// Scores: The score submissions.
	Scores []*ScoreSubmission `json:"scores,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerScoreSubmissionList) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScoreSubmissionList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PushToken: This is a JSON template for a push token resource.
type PushToken struct {
	// ClientRevision: The revision of the client SDK used by your
	// application, in the same format that's used by revisions.check. Used
	// to send backward compatible messages. Format:
	// [PLATFORM_TYPE]:[VERSION_NUMBER]. Possible values of PLATFORM_TYPE
	// are:
	// - IOS - Push token is for iOS
	ClientRevision string `json:"clientRevision,omitempty"`

	// Id: Unique identifier for this push token.
	Id *PushTokenId `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#pushToken.
	Kind string `json:"kind,omitempty"`

	// Language: The preferred language for notifications that are sent
	// using this token.
	Language string `json:"language,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ClientRevision") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PushToken) MarshalJSON() ([]byte, error) {
	type noMethod PushToken
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PushTokenId: This is a JSON template for a push token ID resource.
type PushTokenId struct {
	// Ios: A push token ID for iOS devices.
	Ios *PushTokenIdIos `json:"ios,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#pushTokenId.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Ios") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PushTokenId) MarshalJSON() ([]byte, error) {
	type noMethod PushTokenId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PushTokenIdIos: A push token ID for iOS devices.
type PushTokenIdIos struct {
	// ApnsDeviceToken: Device token supplied by an iOS system call to
	// register for remote notifications. Encode this field as web-safe
	// base64.
	ApnsDeviceToken string `json:"apns_device_token,omitempty"`

	// ApnsEnvironment: Indicates whether this token should be used for the
	// production or sandbox APNS server.
	ApnsEnvironment string `json:"apns_environment,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ApnsDeviceToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PushTokenIdIos) MarshalJSON() ([]byte, error) {
	type noMethod PushTokenIdIos
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Quest: This is a JSON template for a Quest resource.
type Quest struct {
	// AcceptedTimestampMillis: The timestamp at which the user accepted the
	// quest in milliseconds since the epoch in UTC. Only present if the
	// player has accepted the quest.
	AcceptedTimestampMillis int64 `json:"acceptedTimestampMillis,omitempty,string"`

	// ApplicationId: The ID of the application this quest is part of.
	ApplicationId string `json:"applicationId,omitempty"`

	// BannerUrl: The banner image URL for the quest.
	BannerUrl string `json:"bannerUrl,omitempty"`

	// Description: The description of the quest.
	Description string `json:"description,omitempty"`

	// EndTimestampMillis: The timestamp at which the quest ceases to be
	// active in milliseconds since the epoch in UTC.
	EndTimestampMillis int64 `json:"endTimestampMillis,omitempty,string"`

	// IconUrl: The icon image URL for the quest.
	IconUrl string `json:"iconUrl,omitempty"`

	// Id: The ID of the quest.
	Id string `json:"id,omitempty"`

	// IsDefaultBannerUrl: Indicates whether the banner image being returned
	// is a default image, or is game-provided.
	IsDefaultBannerUrl bool `json:"isDefaultBannerUrl,omitempty"`

	// IsDefaultIconUrl: Indicates whether the icon image being returned is
	// a default image, or is game-provided.
	IsDefaultIconUrl bool `json:"isDefaultIconUrl,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#quest.
	Kind string `json:"kind,omitempty"`

	// LastUpdatedTimestampMillis: The timestamp at which the quest was last
	// updated by the user in milliseconds since the epoch in UTC. Only
	// present if the player has accepted the quest.
	LastUpdatedTimestampMillis int64 `json:"lastUpdatedTimestampMillis,omitempty,string"`

	// Milestones: The quest milestones.
	Milestones []*QuestMilestone `json:"milestones,omitempty"`

	// Name: The name of the quest.
	Name string `json:"name,omitempty"`

	// NotifyTimestampMillis: The timestamp at which the user should be
	// notified that the quest will end soon in milliseconds since the epoch
	// in UTC.
	NotifyTimestampMillis int64 `json:"notifyTimestampMillis,omitempty,string"`

	// StartTimestampMillis: The timestamp at which the quest becomes active
	// in milliseconds since the epoch in UTC.
	StartTimestampMillis int64 `json:"startTimestampMillis,omitempty,string"`

	// State: The state of the quest.
	// Possible values are:
	// - "UPCOMING": The quest is upcoming. The user can see the quest, but
	// cannot accept it until it is open.
	// - "OPEN": The quest is currently open and may be accepted at this
	// time.
	// - "ACCEPTED": The user is currently participating in this quest.
	// - "COMPLETED": The user has completed the quest.
	// - "FAILED": The quest was attempted but was not completed before the
	// deadline expired.
	// - "EXPIRED": The quest has expired and was not accepted.
	// - "DELETED": The quest should be deleted from the local database.
	State string `json:"state,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g.
	// "AcceptedTimestampMillis") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Quest) MarshalJSON() ([]byte, error) {
	type noMethod Quest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QuestContribution: This is a JSON template for a Quest Criterion
// Contribution resource.
type QuestContribution struct {
	// FormattedValue: The formatted value of the contribution as a string.
	// Format depends on the configuration for the associated event
	// definition in the Play Games Developer Console.
	FormattedValue string `json:"formattedValue,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#questContribution.
	Kind string `json:"kind,omitempty"`

	// Value: The value of the contribution.
	Value int64 `json:"value,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "FormattedValue") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *QuestContribution) MarshalJSON() ([]byte, error) {
	type noMethod QuestContribution
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QuestCriterion: This is a JSON template for a Quest Criterion
// resource.
type QuestCriterion struct {
	// CompletionContribution: The total number of times the associated
	// event must be incremented for the player to complete this quest.
	CompletionContribution *QuestContribution `json:"completionContribution,omitempty"`

	// CurrentContribution: The number of increments the player has made
	// toward the completion count event increments required to complete the
	// quest. This value will not exceed the completion contribution.
	// There will be no currentContribution until the player has accepted
	// the quest.
	CurrentContribution *QuestContribution `json:"currentContribution,omitempty"`

	// EventId: The ID of the event the criterion corresponds to.
	EventId string `json:"eventId,omitempty"`

	// InitialPlayerProgress: The value of the event associated with this
	// quest at the time that the quest was accepted. This value may change
	// if event increments that took place before the start of quest are
	// uploaded after the quest starts.
	// There will be no initialPlayerProgress until the player has accepted
	// the quest.
	InitialPlayerProgress *QuestContribution `json:"initialPlayerProgress,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#questCriterion.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CompletionContribution") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *QuestCriterion) MarshalJSON() ([]byte, error) {
	type noMethod QuestCriterion
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QuestListResponse: This is a JSON template for a list of quest
// objects.
type QuestListResponse struct {
	// Items: The quests.
	Items []*Quest `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#questListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results.
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

func (s *QuestListResponse) MarshalJSON() ([]byte, error) {
	type noMethod QuestListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QuestMilestone: This is a JSON template for a Quest Milestone
// resource.
type QuestMilestone struct {
	// CompletionRewardData: The completion reward data of the milestone,
	// represented as a Base64-encoded string. This is a developer-specified
	// binary blob with size between 0 and 2 KB before encoding.
	CompletionRewardData string `json:"completionRewardData,omitempty"`

	// Criteria: The criteria of the milestone.
	Criteria []*QuestCriterion `json:"criteria,omitempty"`

	// Id: The milestone ID.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#questMilestone.
	Kind string `json:"kind,omitempty"`

	// State: The current state of the milestone.
	// Possible values are:
	// - "COMPLETED_NOT_CLAIMED" - The milestone is complete, but has not
	// yet been claimed.
	// - "CLAIMED" - The milestone is complete and has been claimed.
	// - "NOT_COMPLETED" - The milestone has not yet been completed.
	// - "NOT_STARTED" - The milestone is for a quest that has not yet been
	// accepted.
	State string `json:"state,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CompletionRewardData") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *QuestMilestone) MarshalJSON() ([]byte, error) {
	type noMethod QuestMilestone
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RevisionCheckResponse: This is a JSON template for the result of
// checking a revision.
type RevisionCheckResponse struct {
	// ApiVersion: The version of the API this client revision should use
	// when calling API methods.
	ApiVersion string `json:"apiVersion,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#revisionCheckResponse.
	Kind string `json:"kind,omitempty"`

	// RevisionStatus: The result of the revision check.
	// Possible values are:
	// - "OK" - The revision being used is current.
	// - "DEPRECATED" - There is currently a newer version available, but
	// the revision being used still works.
	// - "INVALID" - The revision being used is not supported in any
	// released version.
	RevisionStatus string `json:"revisionStatus,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ApiVersion") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RevisionCheckResponse) MarshalJSON() ([]byte, error) {
	type noMethod RevisionCheckResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Room: This is a JSON template for a room resource object.
type Room struct {
	// ApplicationId: The ID of the application being played.
	ApplicationId string `json:"applicationId,omitempty"`

	// AutoMatchingCriteria: Criteria for auto-matching players into this
	// room.
	AutoMatchingCriteria *RoomAutoMatchingCriteria `json:"autoMatchingCriteria,omitempty"`

	// AutoMatchingStatus: Auto-matching status for this room. Not set if
	// the room is not currently in the auto-matching queue.
	AutoMatchingStatus *RoomAutoMatchStatus `json:"autoMatchingStatus,omitempty"`

	// CreationDetails: Details about the room creation.
	CreationDetails *RoomModification `json:"creationDetails,omitempty"`

	// Description: This short description is generated by our servers and
	// worded relative to the player requesting the room. It is intended to
	// be displayed when the room is shown in a list (that is, an invitation
	// to a room.)
	Description string `json:"description,omitempty"`

	// InviterId: The ID of the participant that invited the user to the
	// room. Not set if the user was not invited to the room.
	InviterId string `json:"inviterId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#room.
	Kind string `json:"kind,omitempty"`

	// LastUpdateDetails: Details about the last update to the room.
	LastUpdateDetails *RoomModification `json:"lastUpdateDetails,omitempty"`

	// Participants: The participants involved in the room, along with their
	// statuses. Includes participants who have left or declined
	// invitations.
	Participants []*RoomParticipant `json:"participants,omitempty"`

	// RoomId: Globally unique ID for a room.
	RoomId string `json:"roomId,omitempty"`

	// RoomStatusVersion: The version of the room status: an increasing
	// counter, used by the client to ignore out-of-order updates to room
	// status.
	RoomStatusVersion int64 `json:"roomStatusVersion,omitempty"`

	// Status: The status of the room.
	// Possible values are:
	// - "ROOM_INVITING" - One or more players have been invited and not
	// responded.
	// - "ROOM_AUTO_MATCHING" - One or more slots need to be filled by
	// auto-matching.
	// - "ROOM_CONNECTING" - Players have joined and are connecting to each
	// other (either before or after auto-matching).
	// - "ROOM_ACTIVE" - All players have joined and connected to each
	// other.
	// - "ROOM_DELETED" - The room should no longer be shown on the client.
	// Returned in sync calls when a player joins a room (as a tombstone),
	// or for rooms where all joined participants have left.
	Status string `json:"status,omitempty"`

	// Variant: The variant / mode of the application being played; can be
	// any integer value, or left blank.
	Variant int64 `json:"variant,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ApplicationId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Room) MarshalJSON() ([]byte, error) {
	type noMethod Room
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomAutoMatchStatus: This is a JSON template for status of room
// automatching that is in progress.
type RoomAutoMatchStatus struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomAutoMatchStatus.
	Kind string `json:"kind,omitempty"`

	// WaitEstimateSeconds: An estimate for the amount of time (in seconds)
	// that auto-matching is expected to take to complete.
	WaitEstimateSeconds int64 `json:"waitEstimateSeconds,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomAutoMatchStatus) MarshalJSON() ([]byte, error) {
	type noMethod RoomAutoMatchStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomAutoMatchingCriteria: This is a JSON template for a room
// auto-match criteria object.
type RoomAutoMatchingCriteria struct {
	// ExclusiveBitmask: A bitmask indicating when auto-matches are valid.
	// When ANDed with other exclusive bitmasks, the result must be zero.
	// Can be used to support exclusive roles within a game.
	ExclusiveBitmask int64 `json:"exclusiveBitmask,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomAutoMatchingCriteria.
	Kind string `json:"kind,omitempty"`

	// MaxAutoMatchingPlayers: The maximum number of players that should be
	// added to the room by auto-matching.
	MaxAutoMatchingPlayers int64 `json:"maxAutoMatchingPlayers,omitempty"`

	// MinAutoMatchingPlayers: The minimum number of players that should be
	// added to the room by auto-matching.
	MinAutoMatchingPlayers int64 `json:"minAutoMatchingPlayers,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ExclusiveBitmask") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomAutoMatchingCriteria) MarshalJSON() ([]byte, error) {
	type noMethod RoomAutoMatchingCriteria
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomClientAddress: This is a JSON template for the client address
// when setting up a room.
type RoomClientAddress struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomClientAddress.
	Kind string `json:"kind,omitempty"`

	// XmppAddress: The XMPP address of the client on the Google Games XMPP
	// network.
	XmppAddress string `json:"xmppAddress,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomClientAddress) MarshalJSON() ([]byte, error) {
	type noMethod RoomClientAddress
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomCreateRequest: This is a JSON template for a room creation
// request.
type RoomCreateRequest struct {
	// AutoMatchingCriteria: Criteria for auto-matching players into this
	// room.
	AutoMatchingCriteria *RoomAutoMatchingCriteria `json:"autoMatchingCriteria,omitempty"`

	// Capabilities: The capabilities that this client supports for realtime
	// communication.
	Capabilities []string `json:"capabilities,omitempty"`

	// ClientAddress: Client address for the player creating the room.
	ClientAddress *RoomClientAddress `json:"clientAddress,omitempty"`

	// InvitedPlayerIds: The player IDs to invite to the room.
	InvitedPlayerIds []string `json:"invitedPlayerIds,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomCreateRequest.
	Kind string `json:"kind,omitempty"`

	// NetworkDiagnostics: Network diagnostics for the client creating the
	// room.
	NetworkDiagnostics *NetworkDiagnostics `json:"networkDiagnostics,omitempty"`

	// RequestId: A randomly generated numeric ID. This number is used at
	// the server to ensure that the request is handled correctly across
	// retries.
	RequestId int64 `json:"requestId,omitempty,string"`

	// Variant: The variant / mode of the application to be played. This can
	// be any integer value, or left blank. You should use a small number of
	// variants to keep the auto-matching pool as large as possible.
	Variant int64 `json:"variant,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "AutoMatchingCriteria") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomCreateRequest) MarshalJSON() ([]byte, error) {
	type noMethod RoomCreateRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomJoinRequest: This is a JSON template for a join room request.
type RoomJoinRequest struct {
	// Capabilities: The capabilities that this client supports for realtime
	// communication.
	Capabilities []string `json:"capabilities,omitempty"`

	// ClientAddress: Client address for the player joining the room.
	ClientAddress *RoomClientAddress `json:"clientAddress,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomJoinRequest.
	Kind string `json:"kind,omitempty"`

	// NetworkDiagnostics: Network diagnostics for the client joining the
	// room.
	NetworkDiagnostics *NetworkDiagnostics `json:"networkDiagnostics,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Capabilities") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomJoinRequest) MarshalJSON() ([]byte, error) {
	type noMethod RoomJoinRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomLeaveDiagnostics: This is a JSON template for room leave
// diagnostics.
type RoomLeaveDiagnostics struct {
	// AndroidNetworkSubtype: Android network subtype.
	// http://developer.android.com/reference/android/net/NetworkInfo.html#getSubtype()
	AndroidNetworkSubtype int64 `json:"androidNetworkSubtype,omitempty"`

	// AndroidNetworkType: Android network type.
	// http://developer.android.com/reference/android/net/NetworkInfo.html#getType()
	AndroidNetworkType int64 `json:"androidNetworkType,omitempty"`

	// IosNetworkType: iOS network type as defined in Reachability.h.
	IosNetworkType int64 `json:"iosNetworkType,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomLeaveDiagnostics.
	Kind string `json:"kind,omitempty"`

	// NetworkOperatorCode: The MCC+MNC code for the client's network
	// connection. On Android:
	// http://developer.android.com/reference/android/telephony/TelephonyManager.html#getNetworkOperator() On iOS, see:
	// https://developer.apple.com/library/ios/documentation/NetworkingInternet/Reference/CTCarrier/Reference/Reference.html
	NetworkOperatorCode string `json:"networkOperatorCode,omitempty"`

	// NetworkOperatorName: The name of the carrier of the client's network
	// connection. On Android:
	// http://developer.android.com/reference/android/telephony/TelephonyManager.html#getNetworkOperatorName() On iOS:
	// https://developer.apple.com/library/ios/documentation/NetworkingInternet/Reference/CTCarrier/Reference/Reference.html#//apple_ref/occ/instp/CTCarrier/carrierName
	NetworkOperatorName string `json:"networkOperatorName,omitempty"`

	// PeerSession: Diagnostics about all peer sessions.
	PeerSession []*PeerSessionDiagnostics `json:"peerSession,omitempty"`

	// SocketsUsed: Whether or not sockets were used.
	SocketsUsed bool `json:"socketsUsed,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "AndroidNetworkSubtype") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomLeaveDiagnostics) MarshalJSON() ([]byte, error) {
	type noMethod RoomLeaveDiagnostics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomLeaveRequest: This is a JSON template for a leave room request.
type RoomLeaveRequest struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomLeaveRequest.
	Kind string `json:"kind,omitempty"`

	// LeaveDiagnostics: Diagnostics for a player leaving the room.
	LeaveDiagnostics *RoomLeaveDiagnostics `json:"leaveDiagnostics,omitempty"`

	// Reason: Reason for leaving the match.
	// Possible values are:
	// - "PLAYER_LEFT" - The player chose to leave the room..
	// - "GAME_LEFT" - The game chose to remove the player from the room.
	// - "REALTIME_ABANDONED" - The player switched to another application
	// and abandoned the room.
	// - "REALTIME_PEER_CONNECTION_FAILURE" - The client was unable to
	// establish a connection to other peer(s).
	// - "REALTIME_SERVER_CONNECTION_FAILURE" - The client was unable to
	// communicate with the server.
	// - "REALTIME_SERVER_ERROR" - The client received an error response
	// when it tried to communicate with the server.
	// - "REALTIME_TIMEOUT" - The client timed out while waiting for a room.
	//
	// - "REALTIME_CLIENT_DISCONNECTING" - The client disconnects without
	// first calling Leave.
	// - "REALTIME_SIGN_OUT" - The user signed out of G+ while in the room.
	//
	// - "REALTIME_GAME_CRASHED" - The game crashed.
	// - "REALTIME_ROOM_SERVICE_CRASHED" - RoomAndroidService crashed.
	// - "REALTIME_DIFFERENT_CLIENT_ROOM_OPERATION" - Another client is
	// trying to enter a room.
	// - "REALTIME_SAME_CLIENT_ROOM_OPERATION" - The same client is trying
	// to enter a new room.
	Reason string `json:"reason,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomLeaveRequest) MarshalJSON() ([]byte, error) {
	type noMethod RoomLeaveRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomList: This is a JSON template for a list of rooms.
type RoomList struct {
	// Items: The rooms.
	Items []*Room `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomList.
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

func (s *RoomList) MarshalJSON() ([]byte, error) {
	type noMethod RoomList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomModification: This is a JSON template for room modification
// metadata.
type RoomModification struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomModification.
	Kind string `json:"kind,omitempty"`

	// ModifiedTimestampMillis: The timestamp at which they modified the
	// room, in milliseconds since the epoch in UTC.
	ModifiedTimestampMillis int64 `json:"modifiedTimestampMillis,omitempty,string"`

	// ParticipantId: The ID of the participant that modified the room.
	ParticipantId string `json:"participantId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomModification) MarshalJSON() ([]byte, error) {
	type noMethod RoomModification
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomP2PStatus: This is a JSON template for an update on the status of
// a peer in a room.
type RoomP2PStatus struct {
	// ConnectionSetupLatencyMillis: The amount of time in milliseconds it
	// took to establish connections with this peer.
	ConnectionSetupLatencyMillis int64 `json:"connectionSetupLatencyMillis,omitempty"`

	// Error: The error code in event of a failure.
	// Possible values are:
	// - "P2P_FAILED" - The client failed to establish a P2P connection with
	// the peer.
	// - "PRESENCE_FAILED" - The client failed to register to receive P2P
	// connections.
	// - "RELAY_SERVER_FAILED" - The client received an error when trying to
	// use the relay server to establish a P2P connection with the peer.
	Error string `json:"error,omitempty"`

	// ErrorReason: More detailed diagnostic message returned in event of a
	// failure.
	ErrorReason string `json:"error_reason,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomP2PStatus.
	Kind string `json:"kind,omitempty"`

	// ParticipantId: The ID of the participant.
	ParticipantId string `json:"participantId,omitempty"`

	// Status: The status of the peer in the room.
	// Possible values are:
	// - "CONNECTION_ESTABLISHED" - The client established a P2P connection
	// with the peer.
	// - "CONNECTION_FAILED" - The client failed to establish directed
	// presence with the peer.
	Status string `json:"status,omitempty"`

	// UnreliableRoundtripLatencyMillis: The amount of time in milliseconds
	// it took to send packets back and forth on the unreliable channel with
	// this peer.
	UnreliableRoundtripLatencyMillis int64 `json:"unreliableRoundtripLatencyMillis,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ConnectionSetupLatencyMillis") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomP2PStatus) MarshalJSON() ([]byte, error) {
	type noMethod RoomP2PStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomP2PStatuses: This is a JSON template for an update on the status
// of peers in a room.
type RoomP2PStatuses struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomP2PStatuses.
	Kind string `json:"kind,omitempty"`

	// Updates: The updates for the peers.
	Updates []*RoomP2PStatus `json:"updates,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomP2PStatuses) MarshalJSON() ([]byte, error) {
	type noMethod RoomP2PStatuses
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomParticipant: This is a JSON template for a participant in a room.
type RoomParticipant struct {
	// AutoMatched: True if this participant was auto-matched with the
	// requesting player.
	AutoMatched bool `json:"autoMatched,omitempty"`

	// AutoMatchedPlayer: Information about a player that has been
	// anonymously auto-matched against the requesting player. (Either
	// player or autoMatchedPlayer will be set.)
	AutoMatchedPlayer *AnonymousPlayer `json:"autoMatchedPlayer,omitempty"`

	// Capabilities: The capabilities which can be used when communicating
	// with this participant.
	Capabilities []string `json:"capabilities,omitempty"`

	// ClientAddress: Client address for the participant.
	ClientAddress *RoomClientAddress `json:"clientAddress,omitempty"`

	// Connected: True if this participant is in the fully connected set of
	// peers in the room.
	Connected bool `json:"connected,omitempty"`

	// Id: An identifier for the participant in the scope of the room.
	// Cannot be used to identify a player across rooms or in other
	// contexts.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomParticipant.
	Kind string `json:"kind,omitempty"`

	// LeaveReason: The reason the participant left the room; populated if
	// the participant status is PARTICIPANT_LEFT.
	// Possible values are:
	// - "PLAYER_LEFT" - The player explicitly chose to leave the room.
	// - "GAME_LEFT" - The game chose to remove the player from the room.
	// - "ABANDONED" - The player switched to another application and
	// abandoned the room.
	// - "PEER_CONNECTION_FAILURE" - The client was unable to establish or
	// maintain a connection to other peer(s) in the room.
	// - "SERVER_ERROR" - The client received an error response when it
	// tried to communicate with the server.
	// - "TIMEOUT" - The client timed out while waiting for players to join
	// and connect.
	// - "PRESENCE_FAILURE" - The client's XMPP connection ended abruptly.
	LeaveReason string `json:"leaveReason,omitempty"`

	// Player: Information about the player. Not populated if this player
	// was anonymously auto-matched against the requesting player. (Either
	// player or autoMatchedPlayer will be set.)
	Player *Player `json:"player,omitempty"`

	// Status: The status of the participant with respect to the
	// room.
	// Possible values are:
	// - "PARTICIPANT_INVITED" - The participant has been invited to join
	// the room, but has not yet responded.
	// - "PARTICIPANT_JOINED" - The participant has joined the room (either
	// after creating it or accepting an invitation.)
	// - "PARTICIPANT_DECLINED" - The participant declined an invitation to
	// join the room.
	// - "PARTICIPANT_LEFT" - The participant joined the room and then left
	// it.
	Status string `json:"status,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AutoMatched") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomParticipant) MarshalJSON() ([]byte, error) {
	type noMethod RoomParticipant
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RoomStatus: This is a JSON template for the status of a room that the
// player has joined.
type RoomStatus struct {
	// AutoMatchingStatus: Auto-matching status for this room. Not set if
	// the room is not currently in the automatching queue.
	AutoMatchingStatus *RoomAutoMatchStatus `json:"autoMatchingStatus,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#roomStatus.
	Kind string `json:"kind,omitempty"`

	// Participants: The participants involved in the room, along with their
	// statuses. Includes participants who have left or declined
	// invitations.
	Participants []*RoomParticipant `json:"participants,omitempty"`

	// RoomId: Globally unique ID for a room.
	RoomId string `json:"roomId,omitempty"`

	// Status: The status of the room.
	// Possible values are:
	// - "ROOM_INVITING" - One or more players have been invited and not
	// responded.
	// - "ROOM_AUTO_MATCHING" - One or more slots need to be filled by
	// auto-matching.
	// - "ROOM_CONNECTING" - Players have joined are connecting to each
	// other (either before or after auto-matching).
	// - "ROOM_ACTIVE" - All players have joined and connected to each
	// other.
	// - "ROOM_DELETED" - All joined players have left.
	Status string `json:"status,omitempty"`

	// StatusVersion: The version of the status for the room: an increasing
	// counter, used by the client to ignore out-of-order updates to room
	// status.
	StatusVersion int64 `json:"statusVersion,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AutoMatchingStatus")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RoomStatus) MarshalJSON() ([]byte, error) {
	type noMethod RoomStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ScoreSubmission: This is a JSON template for a request to submit a
// score to leaderboards.
type ScoreSubmission struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#scoreSubmission.
	Kind string `json:"kind,omitempty"`

	// LeaderboardId: The leaderboard this score is being submitted to.
	LeaderboardId string `json:"leaderboardId,omitempty"`

	// Score: The new score being submitted.
	Score int64 `json:"score,omitempty,string"`

	// ScoreTag: Additional information about this score. Values will
	// contain no more than 64 URI-safe characters as defined by section 2.3
	// of RFC 3986.
	ScoreTag string `json:"scoreTag,omitempty"`

	// Signature: Signature Values will contain URI-safe characters as
	// defined by section 2.3 of RFC 3986.
	Signature string `json:"signature,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ScoreSubmission) MarshalJSON() ([]byte, error) {
	type noMethod ScoreSubmission
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Snapshot: This is a JSON template for an snapshot object.
type Snapshot struct {
	// CoverImage: The cover image of this snapshot. May be absent if there
	// is no image.
	CoverImage *SnapshotImage `json:"coverImage,omitempty"`

	// Description: The description of this snapshot.
	Description string `json:"description,omitempty"`

	// DriveId: The ID of the file underlying this snapshot in the Drive
	// API. Only present if the snapshot is a view on a Drive file and the
	// file is owned by the caller.
	DriveId string `json:"driveId,omitempty"`

	// DurationMillis: The duration associated with this snapshot, in
	// millis.
	DurationMillis int64 `json:"durationMillis,omitempty,string"`

	// Id: The ID of the snapshot.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#snapshot.
	Kind string `json:"kind,omitempty"`

	// LastModifiedMillis: The timestamp (in millis since Unix epoch) of the
	// last modification to this snapshot.
	LastModifiedMillis int64 `json:"lastModifiedMillis,omitempty,string"`

	// ProgressValue: The progress value (64-bit integer set by developer)
	// associated with this snapshot.
	ProgressValue int64 `json:"progressValue,omitempty,string"`

	// Title: The title of this snapshot.
	Title string `json:"title,omitempty"`

	// Type: The type of this snapshot.
	// Possible values are:
	// - "SAVE_GAME" - A snapshot representing a save game.
	Type string `json:"type,omitempty"`

	// UniqueName: The unique name provided when the snapshot was created.
	UniqueName string `json:"uniqueName,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CoverImage") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Snapshot) MarshalJSON() ([]byte, error) {
	type noMethod Snapshot
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SnapshotImage: This is a JSON template for an image of a snapshot.
type SnapshotImage struct {
	// Height: The height of the image.
	Height int64 `json:"height,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#snapshotImage.
	Kind string `json:"kind,omitempty"`

	// MimeType: The MIME type of the image.
	MimeType string `json:"mime_type,omitempty"`

	// Url: The URL of the image. This URL may be invalidated at any time
	// and should not be cached.
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

func (s *SnapshotImage) MarshalJSON() ([]byte, error) {
	type noMethod SnapshotImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SnapshotListResponse: This is a JSON template for a list of snapshot
// objects.
type SnapshotListResponse struct {
	// Items: The snapshots.
	Items []*Snapshot `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#snapshotListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Token corresponding to the next page of results. If
	// there are no more results, the token is omitted.
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

func (s *SnapshotListResponse) MarshalJSON() ([]byte, error) {
	type noMethod SnapshotListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedAutoMatchingCriteria: This is a JSON template for an
// turn-based auto-match criteria object.
type TurnBasedAutoMatchingCriteria struct {
	// ExclusiveBitmask: A bitmask indicating when auto-matches are valid.
	// When ANDed with other exclusive bitmasks, the result must be zero.
	// Can be used to support exclusive roles within a game.
	ExclusiveBitmask int64 `json:"exclusiveBitmask,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedAutoMatchingCriteria.
	Kind string `json:"kind,omitempty"`

	// MaxAutoMatchingPlayers: The maximum number of players that should be
	// added to the match by auto-matching.
	MaxAutoMatchingPlayers int64 `json:"maxAutoMatchingPlayers,omitempty"`

	// MinAutoMatchingPlayers: The minimum number of players that should be
	// added to the match by auto-matching.
	MinAutoMatchingPlayers int64 `json:"minAutoMatchingPlayers,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ExclusiveBitmask") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedAutoMatchingCriteria) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedAutoMatchingCriteria
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatch: This is a JSON template for a turn-based match
// resource object.
type TurnBasedMatch struct {
	// ApplicationId: The ID of the application being played.
	ApplicationId string `json:"applicationId,omitempty"`

	// AutoMatchingCriteria: Criteria for auto-matching players into this
	// match.
	AutoMatchingCriteria *TurnBasedAutoMatchingCriteria `json:"autoMatchingCriteria,omitempty"`

	// CreationDetails: Details about the match creation.
	CreationDetails *TurnBasedMatchModification `json:"creationDetails,omitempty"`

	// Data: The data / game state for this match.
	Data *TurnBasedMatchData `json:"data,omitempty"`

	// Description: This short description is generated by our servers based
	// on turn state and is localized and worded relative to the player
	// requesting the match. It is intended to be displayed when the match
	// is shown in a list.
	Description string `json:"description,omitempty"`

	// InviterId: The ID of the participant that invited the user to the
	// match. Not set if the user was not invited to the match.
	InviterId string `json:"inviterId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatch.
	Kind string `json:"kind,omitempty"`

	// LastUpdateDetails: Details about the last update to the match.
	LastUpdateDetails *TurnBasedMatchModification `json:"lastUpdateDetails,omitempty"`

	// MatchId: Globally unique ID for a turn-based match.
	MatchId string `json:"matchId,omitempty"`

	// MatchNumber: The number of the match in a chain of rematches. Will be
	// set to 1 for the first match and incremented by 1 for each rematch.
	MatchNumber int64 `json:"matchNumber,omitempty"`

	// MatchVersion: The version of this match: an increasing counter, used
	// to avoid out-of-date updates to the match.
	MatchVersion int64 `json:"matchVersion,omitempty"`

	// Participants: The participants involved in the match, along with
	// their statuses. Includes participants who have left or declined
	// invitations.
	Participants []*TurnBasedMatchParticipant `json:"participants,omitempty"`

	// PendingParticipantId: The ID of the participant that is taking a
	// turn.
	PendingParticipantId string `json:"pendingParticipantId,omitempty"`

	// PreviousMatchData: The data / game state for the previous match; set
	// for the first turn of rematches only.
	PreviousMatchData *TurnBasedMatchData `json:"previousMatchData,omitempty"`

	// RematchId: The ID of a rematch of this match. Only set for completed
	// matches that have been rematched.
	RematchId string `json:"rematchId,omitempty"`

	// Results: The results reported for this match.
	Results []*ParticipantResult `json:"results,omitempty"`

	// Status: The status of the match.
	// Possible values are:
	// - "MATCH_AUTO_MATCHING" - One or more slots need to be filled by
	// auto-matching; the match cannot be established until they are filled.
	//
	// - "MATCH_ACTIVE" - The match has started.
	// - "MATCH_COMPLETE" - The match has finished.
	// - "MATCH_CANCELED" - The match was canceled.
	// - "MATCH_EXPIRED" - The match expired due to inactivity.
	// - "MATCH_DELETED" - The match should no longer be shown on the
	// client. Returned only for tombstones for matches when sync is called.
	Status string `json:"status,omitempty"`

	// UserMatchStatus: The status of the current user in the match. Derived
	// from the match type, match status, the user's participant status, and
	// the pending participant for the match.
	// Possible values are:
	// - "USER_INVITED" - The user has been invited to join the match and
	// has not responded yet.
	// - "USER_AWAITING_TURN" - The user is waiting for their turn.
	// - "USER_TURN" - The user has an action to take in the match.
	// - "USER_MATCH_COMPLETED" - The match has ended (it is completed,
	// canceled, or expired.)
	UserMatchStatus string `json:"userMatchStatus,omitempty"`

	// Variant: The variant / mode of the application being played; can be
	// any integer value, or left blank.
	Variant int64 `json:"variant,omitempty"`

	// WithParticipantId: The ID of another participant in the match that
	// can be used when describing the participants the user is playing
	// with.
	WithParticipantId string `json:"withParticipantId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ApplicationId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatch) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatch
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchCreateRequest: This is a JSON template for a turn-based
// match creation request.
type TurnBasedMatchCreateRequest struct {
	// AutoMatchingCriteria: Criteria for auto-matching players into this
	// match.
	AutoMatchingCriteria *TurnBasedAutoMatchingCriteria `json:"autoMatchingCriteria,omitempty"`

	// InvitedPlayerIds: The player ids to invite to the match.
	InvitedPlayerIds []string `json:"invitedPlayerIds,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchCreateRequest.
	Kind string `json:"kind,omitempty"`

	// RequestId: A randomly generated numeric ID. This number is used at
	// the server to ensure that the request is handled correctly across
	// retries.
	RequestId int64 `json:"requestId,omitempty,string"`

	// Variant: The variant / mode of the application to be played. This can
	// be any integer value, or left blank. You should use a small number of
	// variants to keep the auto-matching pool as large as possible.
	Variant int64 `json:"variant,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "AutoMatchingCriteria") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchCreateRequest) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchCreateRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchData: This is a JSON template for a turn-based match
// data object.
type TurnBasedMatchData struct {
	// Data: The byte representation of the data (limited to 128 kB), as a
	// Base64-encoded string with the URL_SAFE encoding option.
	Data string `json:"data,omitempty"`

	// DataAvailable: True if this match has data available but it wasn't
	// returned in a list response; fetching the match individually will
	// retrieve this data.
	DataAvailable bool `json:"dataAvailable,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchData.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Data") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchData) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchData
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchDataRequest: This is a JSON template for sending a
// turn-based match data object.
type TurnBasedMatchDataRequest struct {
	// Data: The byte representation of the data (limited to 128 kB), as a
	// Base64-encoded string with the URL_SAFE encoding option.
	Data string `json:"data,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchDataRequest.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Data") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchDataRequest) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchDataRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchList: This is a JSON template for a list of turn-based
// matches.
type TurnBasedMatchList struct {
	// Items: The matches.
	Items []*TurnBasedMatch `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchList.
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

func (s *TurnBasedMatchList) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchModification: This is a JSON template for turn-based
// match modification metadata.
type TurnBasedMatchModification struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchModification.
	Kind string `json:"kind,omitempty"`

	// ModifiedTimestampMillis: The timestamp at which they modified the
	// match, in milliseconds since the epoch in UTC.
	ModifiedTimestampMillis int64 `json:"modifiedTimestampMillis,omitempty,string"`

	// ParticipantId: The ID of the participant that modified the match.
	ParticipantId string `json:"participantId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchModification) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchModification
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchParticipant: This is a JSON template for a participant
// in a turn-based match.
type TurnBasedMatchParticipant struct {
	// AutoMatched: True if this participant was auto-matched with the
	// requesting player.
	AutoMatched bool `json:"autoMatched,omitempty"`

	// AutoMatchedPlayer: Information about a player that has been
	// anonymously auto-matched against the requesting player. (Either
	// player or autoMatchedPlayer will be set.)
	AutoMatchedPlayer *AnonymousPlayer `json:"autoMatchedPlayer,omitempty"`

	// Id: An identifier for the participant in the scope of the match.
	// Cannot be used to identify a player across matches or in other
	// contexts.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchParticipant.
	Kind string `json:"kind,omitempty"`

	// Player: Information about the player. Not populated if this player
	// was anonymously auto-matched against the requesting player. (Either
	// player or autoMatchedPlayer will be set.)
	Player *Player `json:"player,omitempty"`

	// Status: The status of the participant with respect to the
	// match.
	// Possible values are:
	// - "PARTICIPANT_NOT_INVITED_YET" - The participant is slated to be
	// invited to the match, but the invitation has not been sent; the
	// invite will be sent when it becomes their turn.
	// - "PARTICIPANT_INVITED" - The participant has been invited to join
	// the match, but has not yet responded.
	// - "PARTICIPANT_JOINED" - The participant has joined the match (either
	// after creating it or accepting an invitation.)
	// - "PARTICIPANT_DECLINED" - The participant declined an invitation to
	// join the match.
	// - "PARTICIPANT_LEFT" - The participant joined the match and then left
	// it.
	// - "PARTICIPANT_FINISHED" - The participant finished playing in the
	// match.
	// - "PARTICIPANT_UNRESPONSIVE" - The participant did not take their
	// turn in the allotted time.
	Status string `json:"status,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AutoMatched") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchParticipant) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchParticipant
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchRematch: This is a JSON template for a rematch
// response.
type TurnBasedMatchRematch struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchRematch.
	Kind string `json:"kind,omitempty"`

	// PreviousMatch: The old match that the rematch was created from; will
	// be updated such that the rematchId field will point at the new match.
	PreviousMatch *TurnBasedMatch `json:"previousMatch,omitempty"`

	// Rematch: The newly created match; a rematch of the old match with the
	// same participants.
	Rematch *TurnBasedMatch `json:"rematch,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchRematch) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchRematch
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchResults: This is a JSON template for a turn-based match
// results object.
type TurnBasedMatchResults struct {
	// Data: The final match data.
	Data *TurnBasedMatchDataRequest `json:"data,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchResults.
	Kind string `json:"kind,omitempty"`

	// MatchVersion: The version of the match being updated.
	MatchVersion int64 `json:"matchVersion,omitempty"`

	// Results: The match results for the participants in the match.
	Results []*ParticipantResult `json:"results,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Data") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchResults) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchResults
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchSync: This is a JSON template for a list of turn-based
// matches returned from a sync.
type TurnBasedMatchSync struct {
	// Items: The matches.
	Items []*TurnBasedMatch `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchSync.
	Kind string `json:"kind,omitempty"`

	// MoreAvailable: True if there were more matches available to fetch at
	// the time the response was generated (which were not returned due to
	// page size limits.)
	MoreAvailable bool `json:"moreAvailable,omitempty"`

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

func (s *TurnBasedMatchSync) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchSync
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TurnBasedMatchTurn: This is a JSON template for the object
// representing a turn.
type TurnBasedMatchTurn struct {
	// Data: The shared game state data after the turn is over.
	Data *TurnBasedMatchDataRequest `json:"data,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#turnBasedMatchTurn.
	Kind string `json:"kind,omitempty"`

	// MatchVersion: The version of this match: an increasing counter, used
	// to avoid out-of-date updates to the match.
	MatchVersion int64 `json:"matchVersion,omitempty"`

	// PendingParticipantId: The ID of the participant who should take their
	// turn next. May be set to the current player's participant ID to
	// update match state without changing the turn. If not set, the match
	// will wait for other player(s) to join via automatching; this is only
	// valid if automatch criteria is set on the match with remaining slots
	// for automatched players.
	PendingParticipantId string `json:"pendingParticipantId,omitempty"`

	// Results: The match results for the participants in the match.
	Results []*ParticipantResult `json:"results,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Data") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TurnBasedMatchTurn) MarshalJSON() ([]byte, error) {
	type noMethod TurnBasedMatchTurn
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "games.achievementDefinitions.list":

type AchievementDefinitionsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists all the achievement definitions for your application.
func (r *AchievementDefinitionsService) List() *AchievementDefinitionsListCall {
	c := &AchievementDefinitionsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *AchievementDefinitionsListCall) Language(language string) *AchievementDefinitionsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of achievement resources to return in the response, used for
// paging. For any response, the actual number of achievement resources
// returned may be less than the specified maxResults.
func (c *AchievementDefinitionsListCall) MaxResults(maxResults int64) *AchievementDefinitionsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *AchievementDefinitionsListCall) PageToken(pageToken string) *AchievementDefinitionsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementDefinitionsListCall) Fields(s ...googleapi.Field) *AchievementDefinitionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AchievementDefinitionsListCall) IfNoneMatch(entityTag string) *AchievementDefinitionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementDefinitionsListCall) Context(ctx context.Context) *AchievementDefinitionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementDefinitionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements")
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

// Do executes the "games.achievementDefinitions.list" call.
// Exactly one of *AchievementDefinitionsListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *AchievementDefinitionsListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *AchievementDefinitionsListCall) Do() (*AchievementDefinitionsListResponse, error) {
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
	ret := &AchievementDefinitionsListResponse{
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
	//   "description": "Lists all the achievement definitions for your application.",
	//   "httpMethod": "GET",
	//   "id": "games.achievementDefinitions.list",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of achievement resources to return in the response, used for paging. For any response, the actual number of achievement resources returned may be less than the specified maxResults.",
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
	//   "path": "achievements",
	//   "response": {
	//     "$ref": "AchievementDefinitionsListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.increment":

type AchievementsIncrementCall struct {
	s                *Service
	achievementId    string
	stepsToIncrement int64
	opt_             map[string]interface{}
	ctx_             context.Context
}

// Increment: Increments the steps of the achievement with the given ID
// for the currently authenticated player.
func (r *AchievementsService) Increment(achievementId string, stepsToIncrement int64) *AchievementsIncrementCall {
	c := &AchievementsIncrementCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	c.stepsToIncrement = stepsToIncrement
	return c
}

// RequestId sets the optional parameter "requestId": A randomly
// generated numeric ID for each request specified by the caller. This
// number is used at the server to ensure that the request is handled
// correctly across retries.
func (c *AchievementsIncrementCall) RequestId(requestId int64) *AchievementsIncrementCall {
	c.opt_["requestId"] = requestId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsIncrementCall) Fields(s ...googleapi.Field) *AchievementsIncrementCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsIncrementCall) Context(ctx context.Context) *AchievementsIncrementCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsIncrementCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("stepsToIncrement", fmt.Sprintf("%v", c.stepsToIncrement))
	if v, ok := c.opt_["requestId"]; ok {
		params.Set("requestId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/increment")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.achievements.increment" call.
// Exactly one of *AchievementIncrementResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *AchievementIncrementResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsIncrementCall) Do() (*AchievementIncrementResponse, error) {
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
	ret := &AchievementIncrementResponse{
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
	//   "description": "Increments the steps of the achievement with the given ID for the currently authenticated player.",
	//   "httpMethod": "POST",
	//   "id": "games.achievements.increment",
	//   "parameterOrder": [
	//     "achievementId",
	//     "stepsToIncrement"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "requestId": {
	//       "description": "A randomly generated numeric ID for each request specified by the caller. This number is used at the server to ensure that the request is handled correctly across retries.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "stepsToIncrement": {
	//       "description": "The number of steps to increment.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "required": true,
	//       "type": "integer"
	//     }
	//   },
	//   "path": "achievements/{achievementId}/increment",
	//   "response": {
	//     "$ref": "AchievementIncrementResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.list":

type AchievementsListCall struct {
	s        *Service
	playerId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// List: Lists the progress for all your application's achievements for
// the currently authenticated player.
func (r *AchievementsService) List(playerId string) *AchievementsListCall {
	c := &AchievementsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *AchievementsListCall) Language(language string) *AchievementsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of achievement resources to return in the response, used for
// paging. For any response, the actual number of achievement resources
// returned may be less than the specified maxResults.
func (c *AchievementsListCall) MaxResults(maxResults int64) *AchievementsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *AchievementsListCall) PageToken(pageToken string) *AchievementsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// State sets the optional parameter "state": Tells the server to return
// only achievements with the specified state. If this parameter isn't
// specified, all achievements are returned.
//
// Possible values:
//   "ALL" - List all achievements. This is the default.
//   "HIDDEN" - List only hidden achievements.
//   "REVEALED" - List only revealed achievements.
//   "UNLOCKED" - List only unlocked achievements.
func (c *AchievementsListCall) State(state string) *AchievementsListCall {
	c.opt_["state"] = state
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsListCall) Fields(s ...googleapi.Field) *AchievementsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AchievementsListCall) IfNoneMatch(entityTag string) *AchievementsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsListCall) Context(ctx context.Context) *AchievementsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["state"]; ok {
		params.Set("state", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}/achievements")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId": c.playerId,
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

// Do executes the "games.achievements.list" call.
// Exactly one of *PlayerAchievementListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *PlayerAchievementListResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsListCall) Do() (*PlayerAchievementListResponse, error) {
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
	ret := &PlayerAchievementListResponse{
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
	//   "description": "Lists the progress for all your application's achievements for the currently authenticated player.",
	//   "httpMethod": "GET",
	//   "id": "games.achievements.list",
	//   "parameterOrder": [
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of achievement resources to return in the response, used for paging. For any response, the actual number of achievement resources returned may be less than the specified maxResults.",
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
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "state": {
	//       "description": "Tells the server to return only achievements with the specified state. If this parameter isn't specified, all achievements are returned.",
	//       "enum": [
	//         "ALL",
	//         "HIDDEN",
	//         "REVEALED",
	//         "UNLOCKED"
	//       ],
	//       "enumDescriptions": [
	//         "List all achievements. This is the default.",
	//         "List only hidden achievements.",
	//         "List only revealed achievements.",
	//         "List only unlocked achievements."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}/achievements",
	//   "response": {
	//     "$ref": "PlayerAchievementListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.reveal":

type AchievementsRevealCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Reveal: Sets the state of the achievement with the given ID to
// REVEALED for the currently authenticated player.
func (r *AchievementsService) Reveal(achievementId string) *AchievementsRevealCall {
	c := &AchievementsRevealCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsRevealCall) Fields(s ...googleapi.Field) *AchievementsRevealCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsRevealCall) Context(ctx context.Context) *AchievementsRevealCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsRevealCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/reveal")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.achievements.reveal" call.
// Exactly one of *AchievementRevealResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementRevealResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsRevealCall) Do() (*AchievementRevealResponse, error) {
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
	ret := &AchievementRevealResponse{
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
	//   "description": "Sets the state of the achievement with the given ID to REVEALED for the currently authenticated player.",
	//   "httpMethod": "POST",
	//   "id": "games.achievements.reveal",
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
	//   "path": "achievements/{achievementId}/reveal",
	//   "response": {
	//     "$ref": "AchievementRevealResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.setStepsAtLeast":

type AchievementsSetStepsAtLeastCall struct {
	s             *Service
	achievementId string
	steps         int64
	opt_          map[string]interface{}
	ctx_          context.Context
}

// SetStepsAtLeast: Sets the steps for the currently authenticated
// player towards unlocking an achievement. If the steps parameter is
// less than the current number of steps that the player already gained
// for the achievement, the achievement is not modified.
func (r *AchievementsService) SetStepsAtLeast(achievementId string, steps int64) *AchievementsSetStepsAtLeastCall {
	c := &AchievementsSetStepsAtLeastCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	c.steps = steps
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsSetStepsAtLeastCall) Fields(s ...googleapi.Field) *AchievementsSetStepsAtLeastCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsSetStepsAtLeastCall) Context(ctx context.Context) *AchievementsSetStepsAtLeastCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsSetStepsAtLeastCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("steps", fmt.Sprintf("%v", c.steps))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/setStepsAtLeast")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.achievements.setStepsAtLeast" call.
// Exactly one of *AchievementSetStepsAtLeastResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *AchievementSetStepsAtLeastResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *AchievementsSetStepsAtLeastCall) Do() (*AchievementSetStepsAtLeastResponse, error) {
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
	ret := &AchievementSetStepsAtLeastResponse{
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
	//   "description": "Sets the steps for the currently authenticated player towards unlocking an achievement. If the steps parameter is less than the current number of steps that the player already gained for the achievement, the achievement is not modified.",
	//   "httpMethod": "POST",
	//   "id": "games.achievements.setStepsAtLeast",
	//   "parameterOrder": [
	//     "achievementId",
	//     "steps"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "steps": {
	//       "description": "The minimum value to set the steps to.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "required": true,
	//       "type": "integer"
	//     }
	//   },
	//   "path": "achievements/{achievementId}/setStepsAtLeast",
	//   "response": {
	//     "$ref": "AchievementSetStepsAtLeastResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.unlock":

type AchievementsUnlockCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Unlock: Unlocks this achievement for the currently authenticated
// player.
func (r *AchievementsService) Unlock(achievementId string) *AchievementsUnlockCall {
	c := &AchievementsUnlockCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsUnlockCall) Fields(s ...googleapi.Field) *AchievementsUnlockCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsUnlockCall) Context(ctx context.Context) *AchievementsUnlockCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsUnlockCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/unlock")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.achievements.unlock" call.
// Exactly one of *AchievementUnlockResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementUnlockResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsUnlockCall) Do() (*AchievementUnlockResponse, error) {
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
	ret := &AchievementUnlockResponse{
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
	//   "description": "Unlocks this achievement for the currently authenticated player.",
	//   "httpMethod": "POST",
	//   "id": "games.achievements.unlock",
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
	//   "path": "achievements/{achievementId}/unlock",
	//   "response": {
	//     "$ref": "AchievementUnlockResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.achievements.updateMultiple":

type AchievementsUpdateMultipleCall struct {
	s                                *Service
	achievementupdatemultiplerequest *AchievementUpdateMultipleRequest
	opt_                             map[string]interface{}
	ctx_                             context.Context
}

// UpdateMultiple: Updates multiple achievements for the currently
// authenticated player.
func (r *AchievementsService) UpdateMultiple(achievementupdatemultiplerequest *AchievementUpdateMultipleRequest) *AchievementsUpdateMultipleCall {
	c := &AchievementsUpdateMultipleCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementupdatemultiplerequest = achievementupdatemultiplerequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsUpdateMultipleCall) Fields(s ...googleapi.Field) *AchievementsUpdateMultipleCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsUpdateMultipleCall) Context(ctx context.Context) *AchievementsUpdateMultipleCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsUpdateMultipleCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.achievementupdatemultiplerequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/updateMultiple")
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

// Do executes the "games.achievements.updateMultiple" call.
// Exactly one of *AchievementUpdateMultipleResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *AchievementUpdateMultipleResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *AchievementsUpdateMultipleCall) Do() (*AchievementUpdateMultipleResponse, error) {
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
	ret := &AchievementUpdateMultipleResponse{
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
	//   "description": "Updates multiple achievements for the currently authenticated player.",
	//   "httpMethod": "POST",
	//   "id": "games.achievements.updateMultiple",
	//   "path": "achievements/updateMultiple",
	//   "request": {
	//     "$ref": "AchievementUpdateMultipleRequest"
	//   },
	//   "response": {
	//     "$ref": "AchievementUpdateMultipleResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.applications.get":

type ApplicationsGetCall struct {
	s             *Service
	applicationId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Retrieves the metadata of the application with the given ID. If
// the requested application is not available for the specified
// platformType, the returned response will not include any instance
// data.
func (r *ApplicationsService) Get(applicationId string) *ApplicationsGetCall {
	c := &ApplicationsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ApplicationsGetCall) Language(language string) *ApplicationsGetCall {
	c.opt_["language"] = language
	return c
}

// PlatformType sets the optional parameter "platformType": Restrict
// application details returned to the specific platform.
//
// Possible values:
//   "ANDROID" - Retrieve applications that can be played on Android.
//   "IOS" - Retrieve applications that can be played on iOS.
//   "WEB_APP" - Retrieve applications that can be played on desktop
// web.
func (c *ApplicationsGetCall) PlatformType(platformType string) *ApplicationsGetCall {
	c.opt_["platformType"] = platformType
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ApplicationsGetCall) Fields(s ...googleapi.Field) *ApplicationsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ApplicationsGetCall) IfNoneMatch(entityTag string) *ApplicationsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ApplicationsGetCall) Context(ctx context.Context) *ApplicationsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ApplicationsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["platformType"]; ok {
		params.Set("platformType", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}")
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

// Do executes the "games.applications.get" call.
// Exactly one of *Application or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Application.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ApplicationsGetCall) Do() (*Application, error) {
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
	ret := &Application{
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
	//   "description": "Retrieves the metadata of the application with the given ID. If the requested application is not available for the specified platformType, the returned response will not include any instance data.",
	//   "httpMethod": "GET",
	//   "id": "games.applications.get",
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
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "platformType": {
	//       "description": "Restrict application details returned to the specific platform.",
	//       "enum": [
	//         "ANDROID",
	//         "IOS",
	//         "WEB_APP"
	//       ],
	//       "enumDescriptions": [
	//         "Retrieve applications that can be played on Android.",
	//         "Retrieve applications that can be played on iOS.",
	//         "Retrieve applications that can be played on desktop web."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}",
	//   "response": {
	//     "$ref": "Application"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.applications.played":

type ApplicationsPlayedCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Played: Indicate that the the currently authenticated user is playing
// your application.
func (r *ApplicationsService) Played() *ApplicationsPlayedCall {
	c := &ApplicationsPlayedCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ApplicationsPlayedCall) Fields(s ...googleapi.Field) *ApplicationsPlayedCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ApplicationsPlayedCall) Context(ctx context.Context) *ApplicationsPlayedCall {
	c.ctx_ = ctx
	return c
}

func (c *ApplicationsPlayedCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/played")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.applications.played" call.
func (c *ApplicationsPlayedCall) Do() error {
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
	//   "description": "Indicate that the the currently authenticated user is playing your application.",
	//   "httpMethod": "POST",
	//   "id": "games.applications.played",
	//   "path": "applications/played",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.events.listByPlayer":

type EventsListByPlayerCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ListByPlayer: Returns a list showing the current progress on events
// in this application for the currently authenticated user.
func (r *EventsService) ListByPlayer() *EventsListByPlayerCall {
	c := &EventsListByPlayerCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *EventsListByPlayerCall) Language(language string) *EventsListByPlayerCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of events to return in the response, used for paging. For any
// response, the actual number of events to return may be less than the
// specified maxResults.
func (c *EventsListByPlayerCall) MaxResults(maxResults int64) *EventsListByPlayerCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *EventsListByPlayerCall) PageToken(pageToken string) *EventsListByPlayerCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsListByPlayerCall) Fields(s ...googleapi.Field) *EventsListByPlayerCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *EventsListByPlayerCall) IfNoneMatch(entityTag string) *EventsListByPlayerCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsListByPlayerCall) Context(ctx context.Context) *EventsListByPlayerCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsListByPlayerCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "events")
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

// Do executes the "games.events.listByPlayer" call.
// Exactly one of *PlayerEventListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *PlayerEventListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *EventsListByPlayerCall) Do() (*PlayerEventListResponse, error) {
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
	ret := &PlayerEventListResponse{
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
	//   "description": "Returns a list showing the current progress on events in this application for the currently authenticated user.",
	//   "httpMethod": "GET",
	//   "id": "games.events.listByPlayer",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of events to return in the response, used for paging. For any response, the actual number of events to return may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "events",
	//   "response": {
	//     "$ref": "PlayerEventListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.events.listDefinitions":

type EventsListDefinitionsCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ListDefinitions: Returns a list of the event definitions in this
// application.
func (r *EventsService) ListDefinitions() *EventsListDefinitionsCall {
	c := &EventsListDefinitionsCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *EventsListDefinitionsCall) Language(language string) *EventsListDefinitionsCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of event definitions to return in the response, used for
// paging. For any response, the actual number of event definitions to
// return may be less than the specified maxResults.
func (c *EventsListDefinitionsCall) MaxResults(maxResults int64) *EventsListDefinitionsCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *EventsListDefinitionsCall) PageToken(pageToken string) *EventsListDefinitionsCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsListDefinitionsCall) Fields(s ...googleapi.Field) *EventsListDefinitionsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *EventsListDefinitionsCall) IfNoneMatch(entityTag string) *EventsListDefinitionsCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsListDefinitionsCall) Context(ctx context.Context) *EventsListDefinitionsCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsListDefinitionsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "eventDefinitions")
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

// Do executes the "games.events.listDefinitions" call.
// Exactly one of *EventDefinitionListResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *EventDefinitionListResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *EventsListDefinitionsCall) Do() (*EventDefinitionListResponse, error) {
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
	ret := &EventDefinitionListResponse{
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
	//   "description": "Returns a list of the event definitions in this application.",
	//   "httpMethod": "GET",
	//   "id": "games.events.listDefinitions",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of event definitions to return in the response, used for paging. For any response, the actual number of event definitions to return may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "eventDefinitions",
	//   "response": {
	//     "$ref": "EventDefinitionListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.events.record":

type EventsRecordCall struct {
	s                  *Service
	eventrecordrequest *EventRecordRequest
	opt_               map[string]interface{}
	ctx_               context.Context
}

// Record: Records a batch of changes to the number of times events have
// occurred for the currently authenticated user of this application.
func (r *EventsService) Record(eventrecordrequest *EventRecordRequest) *EventsRecordCall {
	c := &EventsRecordCall{s: r.s, opt_: make(map[string]interface{})}
	c.eventrecordrequest = eventrecordrequest
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *EventsRecordCall) Language(language string) *EventsRecordCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsRecordCall) Fields(s ...googleapi.Field) *EventsRecordCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsRecordCall) Context(ctx context.Context) *EventsRecordCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsRecordCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.eventrecordrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events")
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

// Do executes the "games.events.record" call.
// Exactly one of *EventUpdateResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EventUpdateResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *EventsRecordCall) Do() (*EventUpdateResponse, error) {
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
	ret := &EventUpdateResponse{
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
	//   "description": "Records a batch of changes to the number of times events have occurred for the currently authenticated user of this application.",
	//   "httpMethod": "POST",
	//   "id": "games.events.record",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "events",
	//   "request": {
	//     "$ref": "EventRecordRequest"
	//   },
	//   "response": {
	//     "$ref": "EventUpdateResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.leaderboards.get":

type LeaderboardsGetCall struct {
	s             *Service
	leaderboardId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Retrieves the metadata of the leaderboard with the given ID.
func (r *LeaderboardsService) Get(leaderboardId string) *LeaderboardsGetCall {
	c := &LeaderboardsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *LeaderboardsGetCall) Language(language string) *LeaderboardsGetCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardsGetCall) Fields(s ...googleapi.Field) *LeaderboardsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LeaderboardsGetCall) IfNoneMatch(entityTag string) *LeaderboardsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardsGetCall) Context(ctx context.Context) *LeaderboardsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
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

// Do executes the "games.leaderboards.get" call.
// Exactly one of *Leaderboard or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Leaderboard.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *LeaderboardsGetCall) Do() (*Leaderboard, error) {
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
	ret := &Leaderboard{
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
	//   "description": "Retrieves the metadata of the leaderboard with the given ID.",
	//   "httpMethod": "GET",
	//   "id": "games.leaderboards.get",
	//   "parameterOrder": [
	//     "leaderboardId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}",
	//   "response": {
	//     "$ref": "Leaderboard"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.leaderboards.list":

type LeaderboardsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists all the leaderboard metadata for your application.
func (r *LeaderboardsService) List() *LeaderboardsListCall {
	c := &LeaderboardsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *LeaderboardsListCall) Language(language string) *LeaderboardsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of leaderboards to return in the response. For any response,
// the actual number of leaderboards returned may be less than the
// specified maxResults.
func (c *LeaderboardsListCall) MaxResults(maxResults int64) *LeaderboardsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *LeaderboardsListCall) PageToken(pageToken string) *LeaderboardsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardsListCall) Fields(s ...googleapi.Field) *LeaderboardsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LeaderboardsListCall) IfNoneMatch(entityTag string) *LeaderboardsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardsListCall) Context(ctx context.Context) *LeaderboardsListCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards")
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

// Do executes the "games.leaderboards.list" call.
// Exactly one of *LeaderboardListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *LeaderboardListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LeaderboardsListCall) Do() (*LeaderboardListResponse, error) {
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
	ret := &LeaderboardListResponse{
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
	//   "description": "Lists all the leaderboard metadata for your application.",
	//   "httpMethod": "GET",
	//   "id": "games.leaderboards.list",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of leaderboards to return in the response. For any response, the actual number of leaderboards returned may be less than the specified maxResults.",
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
	//   "path": "leaderboards",
	//   "response": {
	//     "$ref": "LeaderboardListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.metagame.getMetagameConfig":

type MetagameGetMetagameConfigCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// GetMetagameConfig: Return the metagame configuration data for the
// calling application.
func (r *MetagameService) GetMetagameConfig() *MetagameGetMetagameConfigCall {
	c := &MetagameGetMetagameConfigCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MetagameGetMetagameConfigCall) Fields(s ...googleapi.Field) *MetagameGetMetagameConfigCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *MetagameGetMetagameConfigCall) IfNoneMatch(entityTag string) *MetagameGetMetagameConfigCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *MetagameGetMetagameConfigCall) Context(ctx context.Context) *MetagameGetMetagameConfigCall {
	c.ctx_ = ctx
	return c
}

func (c *MetagameGetMetagameConfigCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "metagameConfig")
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

// Do executes the "games.metagame.getMetagameConfig" call.
// Exactly one of *MetagameConfig or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *MetagameConfig.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *MetagameGetMetagameConfigCall) Do() (*MetagameConfig, error) {
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
	ret := &MetagameConfig{
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
	//   "description": "Return the metagame configuration data for the calling application.",
	//   "httpMethod": "GET",
	//   "id": "games.metagame.getMetagameConfig",
	//   "path": "metagameConfig",
	//   "response": {
	//     "$ref": "MetagameConfig"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.metagame.listCategoriesByPlayer":

type MetagameListCategoriesByPlayerCall struct {
	s          *Service
	playerId   string
	collection string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// ListCategoriesByPlayer: List play data aggregated per category for
// the player corresponding to playerId.
func (r *MetagameService) ListCategoriesByPlayer(playerId string, collection string) *MetagameListCategoriesByPlayerCall {
	c := &MetagameListCategoriesByPlayerCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	c.collection = collection
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *MetagameListCategoriesByPlayerCall) Language(language string) *MetagameListCategoriesByPlayerCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of category resources to return in the response, used for
// paging. For any response, the actual number of category resources
// returned may be less than the specified maxResults.
func (c *MetagameListCategoriesByPlayerCall) MaxResults(maxResults int64) *MetagameListCategoriesByPlayerCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *MetagameListCategoriesByPlayerCall) PageToken(pageToken string) *MetagameListCategoriesByPlayerCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MetagameListCategoriesByPlayerCall) Fields(s ...googleapi.Field) *MetagameListCategoriesByPlayerCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *MetagameListCategoriesByPlayerCall) IfNoneMatch(entityTag string) *MetagameListCategoriesByPlayerCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *MetagameListCategoriesByPlayerCall) Context(ctx context.Context) *MetagameListCategoriesByPlayerCall {
	c.ctx_ = ctx
	return c
}

func (c *MetagameListCategoriesByPlayerCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}/categories/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId":   c.playerId,
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

// Do executes the "games.metagame.listCategoriesByPlayer" call.
// Exactly one of *CategoryListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CategoryListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *MetagameListCategoriesByPlayerCall) Do() (*CategoryListResponse, error) {
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
	ret := &CategoryListResponse{
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
	//   "description": "List play data aggregated per category for the player corresponding to playerId.",
	//   "httpMethod": "GET",
	//   "id": "games.metagame.listCategoriesByPlayer",
	//   "parameterOrder": [
	//     "playerId",
	//     "collection"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "The collection of categories for which data will be returned.",
	//       "enum": [
	//         "all"
	//       ],
	//       "enumDescriptions": [
	//         "Retrieve data for all categories. This is the default."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of category resources to return in the response, used for paging. For any response, the actual number of category resources returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}/categories/{collection}",
	//   "response": {
	//     "$ref": "CategoryListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.players.get":

type PlayersGetCall struct {
	s        *Service
	playerId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Retrieves the Player resource with the given ID. To retrieve the
// player for the currently authenticated user, set playerId to me.
func (r *PlayersService) Get(playerId string) *PlayersGetCall {
	c := &PlayersGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *PlayersGetCall) Language(language string) *PlayersGetCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlayersGetCall) Fields(s ...googleapi.Field) *PlayersGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PlayersGetCall) IfNoneMatch(entityTag string) *PlayersGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlayersGetCall) Context(ctx context.Context) *PlayersGetCall {
	c.ctx_ = ctx
	return c
}

func (c *PlayersGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId": c.playerId,
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

// Do executes the "games.players.get" call.
// Exactly one of *Player or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Player.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *PlayersGetCall) Do() (*Player, error) {
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
	ret := &Player{
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
	//   "description": "Retrieves the Player resource with the given ID. To retrieve the player for the currently authenticated user, set playerId to me.",
	//   "httpMethod": "GET",
	//   "id": "games.players.get",
	//   "parameterOrder": [
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}",
	//   "response": {
	//     "$ref": "Player"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.players.list":

type PlayersListCall struct {
	s          *Service
	collection string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: Get the collection of players for the currently authenticated
// user.
func (r *PlayersService) List(collection string) *PlayersListCall {
	c := &PlayersListCall{s: r.s, opt_: make(map[string]interface{})}
	c.collection = collection
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *PlayersListCall) Language(language string) *PlayersListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of player resources to return in the response, used for
// paging. For any response, the actual number of player resources
// returned may be less than the specified maxResults.
func (c *PlayersListCall) MaxResults(maxResults int64) *PlayersListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *PlayersListCall) PageToken(pageToken string) *PlayersListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlayersListCall) Fields(s ...googleapi.Field) *PlayersListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PlayersListCall) IfNoneMatch(entityTag string) *PlayersListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlayersListCall) Context(ctx context.Context) *PlayersListCall {
	c.ctx_ = ctx
	return c
}

func (c *PlayersListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/me/players/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
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

// Do executes the "games.players.list" call.
// Exactly one of *PlayerListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *PlayerListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PlayersListCall) Do() (*PlayerListResponse, error) {
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
	ret := &PlayerListResponse{
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
	//   "description": "Get the collection of players for the currently authenticated user.",
	//   "httpMethod": "GET",
	//   "id": "games.players.list",
	//   "parameterOrder": [
	//     "collection"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "Collection of players being retrieved",
	//       "enum": [
	//         "connected",
	//         "playedWith",
	//         "played_with"
	//       ],
	//       "enumDescriptions": [
	//         "Retrieve a list of players that are also playing this game in reverse chronological order.",
	//         "(DEPRECATED: please use played_with!) Retrieve a list of players you have played a multiplayer game (realtime or turn-based) with recently.",
	//         "Retrieve a list of players you have played a multiplayer game (realtime or turn-based) with recently."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of player resources to return in the response, used for paging. For any response, the actual number of player resources returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/me/players/{collection}",
	//   "response": {
	//     "$ref": "PlayerListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.pushtokens.remove":

type PushtokensRemoveCall struct {
	s           *Service
	pushtokenid *PushTokenId
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Remove: Removes a push token for the current user and application.
// Removing a non-existent push token will report success.
func (r *PushtokensService) Remove(pushtokenid *PushTokenId) *PushtokensRemoveCall {
	c := &PushtokensRemoveCall{s: r.s, opt_: make(map[string]interface{})}
	c.pushtokenid = pushtokenid
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PushtokensRemoveCall) Fields(s ...googleapi.Field) *PushtokensRemoveCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PushtokensRemoveCall) Context(ctx context.Context) *PushtokensRemoveCall {
	c.ctx_ = ctx
	return c
}

func (c *PushtokensRemoveCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.pushtokenid)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "pushtokens/remove")
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

// Do executes the "games.pushtokens.remove" call.
func (c *PushtokensRemoveCall) Do() error {
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
	//   "description": "Removes a push token for the current user and application. Removing a non-existent push token will report success.",
	//   "httpMethod": "POST",
	//   "id": "games.pushtokens.remove",
	//   "path": "pushtokens/remove",
	//   "request": {
	//     "$ref": "PushTokenId"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.pushtokens.update":

type PushtokensUpdateCall struct {
	s         *Service
	pushtoken *PushToken
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Registers a push token for the current user and application.
func (r *PushtokensService) Update(pushtoken *PushToken) *PushtokensUpdateCall {
	c := &PushtokensUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.pushtoken = pushtoken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PushtokensUpdateCall) Fields(s ...googleapi.Field) *PushtokensUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PushtokensUpdateCall) Context(ctx context.Context) *PushtokensUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *PushtokensUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.pushtoken)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "pushtokens")
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

// Do executes the "games.pushtokens.update" call.
func (c *PushtokensUpdateCall) Do() error {
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
	//   "description": "Registers a push token for the current user and application.",
	//   "httpMethod": "PUT",
	//   "id": "games.pushtokens.update",
	//   "path": "pushtokens",
	//   "request": {
	//     "$ref": "PushToken"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.questMilestones.claim":

type QuestMilestonesClaimCall struct {
	s           *Service
	questId     string
	milestoneId string
	requestId   int64
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Claim: Report that a reward for the milestone corresponding to
// milestoneId for the quest corresponding to questId has been claimed
// by the currently authorized user.
func (r *QuestMilestonesService) Claim(questId string, milestoneId string, requestId int64) *QuestMilestonesClaimCall {
	c := &QuestMilestonesClaimCall{s: r.s, opt_: make(map[string]interface{})}
	c.questId = questId
	c.milestoneId = milestoneId
	c.requestId = requestId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestMilestonesClaimCall) Fields(s ...googleapi.Field) *QuestMilestonesClaimCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestMilestonesClaimCall) Context(ctx context.Context) *QuestMilestonesClaimCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestMilestonesClaimCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("requestId", fmt.Sprintf("%v", c.requestId))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/{questId}/milestones/{milestoneId}/claim")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"questId":     c.questId,
		"milestoneId": c.milestoneId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.questMilestones.claim" call.
func (c *QuestMilestonesClaimCall) Do() error {
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
	//   "description": "Report that a reward for the milestone corresponding to milestoneId for the quest corresponding to questId has been claimed by the currently authorized user.",
	//   "httpMethod": "PUT",
	//   "id": "games.questMilestones.claim",
	//   "parameterOrder": [
	//     "questId",
	//     "milestoneId",
	//     "requestId"
	//   ],
	//   "parameters": {
	//     "milestoneId": {
	//       "description": "The ID of the milestone.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "questId": {
	//       "description": "The ID of the quest.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "requestId": {
	//       "description": "A numeric ID to ensure that the request is handled correctly across retries. Your client application must generate this ID randomly.",
	//       "format": "int64",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "quests/{questId}/milestones/{milestoneId}/claim",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.quests.accept":

type QuestsAcceptCall struct {
	s       *Service
	questId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Accept: Indicates that the currently authorized user will participate
// in the quest.
func (r *QuestsService) Accept(questId string) *QuestsAcceptCall {
	c := &QuestsAcceptCall{s: r.s, opt_: make(map[string]interface{})}
	c.questId = questId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *QuestsAcceptCall) Language(language string) *QuestsAcceptCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsAcceptCall) Fields(s ...googleapi.Field) *QuestsAcceptCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsAcceptCall) Context(ctx context.Context) *QuestsAcceptCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsAcceptCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/{questId}/accept")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"questId": c.questId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.quests.accept" call.
// Exactly one of *Quest or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Quest.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *QuestsAcceptCall) Do() (*Quest, error) {
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
	ret := &Quest{
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
	//   "description": "Indicates that the currently authorized user will participate in the quest.",
	//   "httpMethod": "POST",
	//   "id": "games.quests.accept",
	//   "parameterOrder": [
	//     "questId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "questId": {
	//       "description": "The ID of the quest.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "quests/{questId}/accept",
	//   "response": {
	//     "$ref": "Quest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.quests.list":

type QuestsListCall struct {
	s        *Service
	playerId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// List: Get a list of quests for your application and the currently
// authenticated player.
func (r *QuestsService) List(playerId string) *QuestsListCall {
	c := &QuestsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *QuestsListCall) Language(language string) *QuestsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of quest resources to return in the response, used for paging.
// For any response, the actual number of quest resources returned may
// be less than the specified maxResults. Acceptable values are 1 to 50,
// inclusive. (Default: 50).
func (c *QuestsListCall) MaxResults(maxResults int64) *QuestsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *QuestsListCall) PageToken(pageToken string) *QuestsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsListCall) Fields(s ...googleapi.Field) *QuestsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *QuestsListCall) IfNoneMatch(entityTag string) *QuestsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsListCall) Context(ctx context.Context) *QuestsListCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}/quests")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId": c.playerId,
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

// Do executes the "games.quests.list" call.
// Exactly one of *QuestListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *QuestListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *QuestsListCall) Do() (*QuestListResponse, error) {
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
	ret := &QuestListResponse{
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
	//   "description": "Get a list of quests for your application and the currently authenticated player.",
	//   "httpMethod": "GET",
	//   "id": "games.quests.list",
	//   "parameterOrder": [
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of quest resources to return in the response, used for paging. For any response, the actual number of quest resources returned may be less than the specified maxResults. Acceptable values are 1 to 50, inclusive. (Default: 50).",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "50",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}/quests",
	//   "response": {
	//     "$ref": "QuestListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.revisions.check":

type RevisionsCheckCall struct {
	s              *Service
	clientRevision string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Check: Checks whether the games client is out of date.
func (r *RevisionsService) Check(clientRevision string) *RevisionsCheckCall {
	c := &RevisionsCheckCall{s: r.s, opt_: make(map[string]interface{})}
	c.clientRevision = clientRevision
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsCheckCall) Fields(s ...googleapi.Field) *RevisionsCheckCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RevisionsCheckCall) IfNoneMatch(entityTag string) *RevisionsCheckCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsCheckCall) Context(ctx context.Context) *RevisionsCheckCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsCheckCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("clientRevision", fmt.Sprintf("%v", c.clientRevision))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "revisions/check")
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

// Do executes the "games.revisions.check" call.
// Exactly one of *RevisionCheckResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *RevisionCheckResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *RevisionsCheckCall) Do() (*RevisionCheckResponse, error) {
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
	ret := &RevisionCheckResponse{
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
	//   "description": "Checks whether the games client is out of date.",
	//   "httpMethod": "GET",
	//   "id": "games.revisions.check",
	//   "parameterOrder": [
	//     "clientRevision"
	//   ],
	//   "parameters": {
	//     "clientRevision": {
	//       "description": "The revision of the client SDK used by your application. Format:\n[PLATFORM_TYPE]:[VERSION_NUMBER]. Possible values of PLATFORM_TYPE are:\n \n- \"ANDROID\" - Client is running the Android SDK. \n- \"IOS\" - Client is running the iOS SDK. \n- \"WEB_APP\" - Client is running as a Web App.",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "revisions/check",
	//   "response": {
	//     "$ref": "RevisionCheckResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.create":

type RoomsCreateCall struct {
	s                 *Service
	roomcreaterequest *RoomCreateRequest
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Create: Create a room. For internal use by the Games SDK only.
// Calling this method directly is unsupported.
func (r *RoomsService) Create(roomcreaterequest *RoomCreateRequest) *RoomsCreateCall {
	c := &RoomsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomcreaterequest = roomcreaterequest
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsCreateCall) Language(language string) *RoomsCreateCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsCreateCall) Fields(s ...googleapi.Field) *RoomsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsCreateCall) Context(ctx context.Context) *RoomsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.roomcreaterequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/create")
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

// Do executes the "games.rooms.create" call.
// Exactly one of *Room or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Room.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *RoomsCreateCall) Do() (*Room, error) {
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
	ret := &Room{
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
	//   "description": "Create a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.create",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/create",
	//   "request": {
	//     "$ref": "RoomCreateRequest"
	//   },
	//   "response": {
	//     "$ref": "Room"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.decline":

type RoomsDeclineCall struct {
	s      *Service
	roomId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Decline: Decline an invitation to join a room. For internal use by
// the Games SDK only. Calling this method directly is unsupported.
func (r *RoomsService) Decline(roomId string) *RoomsDeclineCall {
	c := &RoomsDeclineCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsDeclineCall) Language(language string) *RoomsDeclineCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsDeclineCall) Fields(s ...googleapi.Field) *RoomsDeclineCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsDeclineCall) Context(ctx context.Context) *RoomsDeclineCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsDeclineCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}/decline")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.rooms.decline" call.
// Exactly one of *Room or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Room.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *RoomsDeclineCall) Do() (*Room, error) {
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
	ret := &Room{
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
	//   "description": "Decline an invitation to join a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.decline",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}/decline",
	//   "response": {
	//     "$ref": "Room"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.dismiss":

type RoomsDismissCall struct {
	s      *Service
	roomId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Dismiss: Dismiss an invitation to join a room. For internal use by
// the Games SDK only. Calling this method directly is unsupported.
func (r *RoomsService) Dismiss(roomId string) *RoomsDismissCall {
	c := &RoomsDismissCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsDismissCall) Fields(s ...googleapi.Field) *RoomsDismissCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsDismissCall) Context(ctx context.Context) *RoomsDismissCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsDismissCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}/dismiss")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.rooms.dismiss" call.
func (c *RoomsDismissCall) Do() error {
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
	//   "description": "Dismiss an invitation to join a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.dismiss",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}/dismiss",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.get":

type RoomsGetCall struct {
	s      *Service
	roomId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Get: Get the data for a room.
func (r *RoomsService) Get(roomId string) *RoomsGetCall {
	c := &RoomsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsGetCall) Language(language string) *RoomsGetCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsGetCall) Fields(s ...googleapi.Field) *RoomsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RoomsGetCall) IfNoneMatch(entityTag string) *RoomsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsGetCall) Context(ctx context.Context) *RoomsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
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

// Do executes the "games.rooms.get" call.
// Exactly one of *Room or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Room.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *RoomsGetCall) Do() (*Room, error) {
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
	ret := &Room{
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
	//   "description": "Get the data for a room.",
	//   "httpMethod": "GET",
	//   "id": "games.rooms.get",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}",
	//   "response": {
	//     "$ref": "Room"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.join":

type RoomsJoinCall struct {
	s               *Service
	roomId          string
	roomjoinrequest *RoomJoinRequest
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Join: Join a room. For internal use by the Games SDK only. Calling
// this method directly is unsupported.
func (r *RoomsService) Join(roomId string, roomjoinrequest *RoomJoinRequest) *RoomsJoinCall {
	c := &RoomsJoinCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	c.roomjoinrequest = roomjoinrequest
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsJoinCall) Language(language string) *RoomsJoinCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsJoinCall) Fields(s ...googleapi.Field) *RoomsJoinCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsJoinCall) Context(ctx context.Context) *RoomsJoinCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsJoinCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.roomjoinrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}/join")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.rooms.join" call.
// Exactly one of *Room or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Room.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *RoomsJoinCall) Do() (*Room, error) {
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
	ret := &Room{
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
	//   "description": "Join a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.join",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}/join",
	//   "request": {
	//     "$ref": "RoomJoinRequest"
	//   },
	//   "response": {
	//     "$ref": "Room"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.leave":

type RoomsLeaveCall struct {
	s                *Service
	roomId           string
	roomleaverequest *RoomLeaveRequest
	opt_             map[string]interface{}
	ctx_             context.Context
}

// Leave: Leave a room. For internal use by the Games SDK only. Calling
// this method directly is unsupported.
func (r *RoomsService) Leave(roomId string, roomleaverequest *RoomLeaveRequest) *RoomsLeaveCall {
	c := &RoomsLeaveCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	c.roomleaverequest = roomleaverequest
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsLeaveCall) Language(language string) *RoomsLeaveCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsLeaveCall) Fields(s ...googleapi.Field) *RoomsLeaveCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsLeaveCall) Context(ctx context.Context) *RoomsLeaveCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsLeaveCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.roomleaverequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}/leave")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.rooms.leave" call.
// Exactly one of *Room or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Room.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *RoomsLeaveCall) Do() (*Room, error) {
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
	ret := &Room{
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
	//   "description": "Leave a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.leave",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}/leave",
	//   "request": {
	//     "$ref": "RoomLeaveRequest"
	//   },
	//   "response": {
	//     "$ref": "Room"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.list":

type RoomsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns invitations to join rooms.
func (r *RoomsService) List() *RoomsListCall {
	c := &RoomsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsListCall) Language(language string) *RoomsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of rooms to return in the response, used for paging. For any
// response, the actual number of rooms to return may be less than the
// specified maxResults.
func (c *RoomsListCall) MaxResults(maxResults int64) *RoomsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *RoomsListCall) PageToken(pageToken string) *RoomsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsListCall) Fields(s ...googleapi.Field) *RoomsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RoomsListCall) IfNoneMatch(entityTag string) *RoomsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsListCall) Context(ctx context.Context) *RoomsListCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms")
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

// Do executes the "games.rooms.list" call.
// Exactly one of *RoomList or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *RoomList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RoomsListCall) Do() (*RoomList, error) {
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
	ret := &RoomList{
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
	//   "description": "Returns invitations to join rooms.",
	//   "httpMethod": "GET",
	//   "id": "games.rooms.list",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of rooms to return in the response, used for paging. For any response, the actual number of rooms to return may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms",
	//   "response": {
	//     "$ref": "RoomList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.rooms.reportStatus":

type RoomsReportStatusCall struct {
	s               *Service
	roomId          string
	roomp2pstatuses *RoomP2PStatuses
	opt_            map[string]interface{}
	ctx_            context.Context
}

// ReportStatus: Updates sent by a client reporting the status of peers
// in a room. For internal use by the Games SDK only. Calling this
// method directly is unsupported.
func (r *RoomsService) ReportStatus(roomId string, roomp2pstatuses *RoomP2PStatuses) *RoomsReportStatusCall {
	c := &RoomsReportStatusCall{s: r.s, opt_: make(map[string]interface{})}
	c.roomId = roomId
	c.roomp2pstatuses = roomp2pstatuses
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *RoomsReportStatusCall) Language(language string) *RoomsReportStatusCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsReportStatusCall) Fields(s ...googleapi.Field) *RoomsReportStatusCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsReportStatusCall) Context(ctx context.Context) *RoomsReportStatusCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsReportStatusCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.roomp2pstatuses)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/{roomId}/reportstatus")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"roomId": c.roomId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.rooms.reportStatus" call.
// Exactly one of *RoomStatus or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *RoomStatus.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RoomsReportStatusCall) Do() (*RoomStatus, error) {
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
	ret := &RoomStatus{
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
	//   "description": "Updates sent by a client reporting the status of peers in a room. For internal use by the Games SDK only. Calling this method directly is unsupported.",
	//   "httpMethod": "POST",
	//   "id": "games.rooms.reportStatus",
	//   "parameterOrder": [
	//     "roomId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "roomId": {
	//       "description": "The ID of the room.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "rooms/{roomId}/reportstatus",
	//   "request": {
	//     "$ref": "RoomP2PStatuses"
	//   },
	//   "response": {
	//     "$ref": "RoomStatus"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.scores.get":

type ScoresGetCall struct {
	s             *Service
	playerId      string
	leaderboardId string
	timeSpan      string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Get high scores, and optionally ranks, in leaderboards for the
// currently authenticated player. For a specific time span,
// leaderboardId can be set to ALL to retrieve data for all leaderboards
// in a given time span.
// NOTE: You cannot ask for 'ALL' leaderboards and 'ALL' timeSpans in
// the same request; only one parameter may be set to 'ALL'.
func (r *ScoresService) Get(playerId string, leaderboardId string, timeSpan string) *ScoresGetCall {
	c := &ScoresGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	c.leaderboardId = leaderboardId
	c.timeSpan = timeSpan
	return c
}

// IncludeRankType sets the optional parameter "includeRankType": The
// types of ranks to return. If the parameter is omitted, no ranks will
// be returned.
//
// Possible values:
//   "ALL" - Retrieve public and social ranks.
//   "PUBLIC" - Retrieve public ranks, if the player is sharing their
// gameplay activity publicly.
//   "SOCIAL" - Retrieve the social rank.
func (c *ScoresGetCall) IncludeRankType(includeRankType string) *ScoresGetCall {
	c.opt_["includeRankType"] = includeRankType
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ScoresGetCall) Language(language string) *ScoresGetCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of leaderboard scores to return in the response. For any
// response, the actual number of leaderboard scores returned may be
// less than the specified maxResults.
func (c *ScoresGetCall) MaxResults(maxResults int64) *ScoresGetCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *ScoresGetCall) PageToken(pageToken string) *ScoresGetCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresGetCall) Fields(s ...googleapi.Field) *ScoresGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ScoresGetCall) IfNoneMatch(entityTag string) *ScoresGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresGetCall) Context(ctx context.Context) *ScoresGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeRankType"]; ok {
		params.Set("includeRankType", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}/leaderboards/{leaderboardId}/scores/{timeSpan}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId":      c.playerId,
		"leaderboardId": c.leaderboardId,
		"timeSpan":      c.timeSpan,
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

// Do executes the "games.scores.get" call.
// Exactly one of *PlayerLeaderboardScoreListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *PlayerLeaderboardScoreListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *ScoresGetCall) Do() (*PlayerLeaderboardScoreListResponse, error) {
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
	ret := &PlayerLeaderboardScoreListResponse{
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
	//   "description": "Get high scores, and optionally ranks, in leaderboards for the currently authenticated player. For a specific time span, leaderboardId can be set to ALL to retrieve data for all leaderboards in a given time span.\nNOTE: You cannot ask for 'ALL' leaderboards and 'ALL' timeSpans in the same request; only one parameter may be set to 'ALL'.",
	//   "httpMethod": "GET",
	//   "id": "games.scores.get",
	//   "parameterOrder": [
	//     "playerId",
	//     "leaderboardId",
	//     "timeSpan"
	//   ],
	//   "parameters": {
	//     "includeRankType": {
	//       "description": "The types of ranks to return. If the parameter is omitted, no ranks will be returned.",
	//       "enum": [
	//         "ALL",
	//         "PUBLIC",
	//         "SOCIAL"
	//       ],
	//       "enumDescriptions": [
	//         "Retrieve public and social ranks.",
	//         "Retrieve public ranks, if the player is sharing their gameplay activity publicly.",
	//         "Retrieve the social rank."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard. Can be set to 'ALL' to retrieve data for all leaderboards for this application.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of leaderboard scores to return in the response. For any response, the actual number of leaderboard scores returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "30",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "timeSpan": {
	//       "description": "The time span for the scores and ranks you're requesting.",
	//       "enum": [
	//         "ALL",
	//         "ALL_TIME",
	//         "DAILY",
	//         "WEEKLY"
	//       ],
	//       "enumDescriptions": [
	//         "Get the high scores for all time spans. If this is used, maxResults values will be ignored.",
	//         "Get the all time high score.",
	//         "List the top scores for the current day.",
	//         "List the top scores for the current week."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}/leaderboards/{leaderboardId}/scores/{timeSpan}",
	//   "response": {
	//     "$ref": "PlayerLeaderboardScoreListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.scores.list":

type ScoresListCall struct {
	s             *Service
	leaderboardId string
	collection    string
	timeSpan      string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists the scores in a leaderboard, starting from the top.
func (r *ScoresService) List(leaderboardId string, collection string, timeSpan string) *ScoresListCall {
	c := &ScoresListCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	c.collection = collection
	c.timeSpan = timeSpan
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ScoresListCall) Language(language string) *ScoresListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of leaderboard scores to return in the response. For any
// response, the actual number of leaderboard scores returned may be
// less than the specified maxResults.
func (c *ScoresListCall) MaxResults(maxResults int64) *ScoresListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *ScoresListCall) PageToken(pageToken string) *ScoresListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresListCall) Fields(s ...googleapi.Field) *ScoresListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ScoresListCall) IfNoneMatch(entityTag string) *ScoresListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresListCall) Context(ctx context.Context) *ScoresListCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("timeSpan", fmt.Sprintf("%v", c.timeSpan))
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}/scores/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
		"collection":    c.collection,
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

// Do executes the "games.scores.list" call.
// Exactly one of *LeaderboardScores or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *LeaderboardScores.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresListCall) Do() (*LeaderboardScores, error) {
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
	ret := &LeaderboardScores{
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
	//   "description": "Lists the scores in a leaderboard, starting from the top.",
	//   "httpMethod": "GET",
	//   "id": "games.scores.list",
	//   "parameterOrder": [
	//     "leaderboardId",
	//     "collection",
	//     "timeSpan"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "The collection of scores you're requesting.",
	//       "enum": [
	//         "PUBLIC",
	//         "SOCIAL"
	//       ],
	//       "enumDescriptions": [
	//         "List all scores in the public leaderboard.",
	//         "List only social scores."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of leaderboard scores to return in the response. For any response, the actual number of leaderboard scores returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "30",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "timeSpan": {
	//       "description": "The time span for the scores and ranks you're requesting.",
	//       "enum": [
	//         "ALL_TIME",
	//         "DAILY",
	//         "WEEKLY"
	//       ],
	//       "enumDescriptions": [
	//         "List the all-time top scores.",
	//         "List the top scores for the current day.",
	//         "List the top scores for the current week."
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}/scores/{collection}",
	//   "response": {
	//     "$ref": "LeaderboardScores"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.scores.listWindow":

type ScoresListWindowCall struct {
	s             *Service
	leaderboardId string
	collection    string
	timeSpan      string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// ListWindow: Lists the scores in a leaderboard around (and including)
// a player's score.
func (r *ScoresService) ListWindow(leaderboardId string, collection string, timeSpan string) *ScoresListWindowCall {
	c := &ScoresListWindowCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	c.collection = collection
	c.timeSpan = timeSpan
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ScoresListWindowCall) Language(language string) *ScoresListWindowCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of leaderboard scores to return in the response. For any
// response, the actual number of leaderboard scores returned may be
// less than the specified maxResults.
func (c *ScoresListWindowCall) MaxResults(maxResults int64) *ScoresListWindowCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *ScoresListWindowCall) PageToken(pageToken string) *ScoresListWindowCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// ResultsAbove sets the optional parameter "resultsAbove": The
// preferred number of scores to return above the player's score. More
// scores may be returned if the player is at the bottom of the
// leaderboard; fewer may be returned if the player is at the top. Must
// be less than or equal to maxResults.
func (c *ScoresListWindowCall) ResultsAbove(resultsAbove int64) *ScoresListWindowCall {
	c.opt_["resultsAbove"] = resultsAbove
	return c
}

// ReturnTopIfAbsent sets the optional parameter "returnTopIfAbsent":
// True if the top scores should be returned when the player is not in
// the leaderboard. Defaults to true.
func (c *ScoresListWindowCall) ReturnTopIfAbsent(returnTopIfAbsent bool) *ScoresListWindowCall {
	c.opt_["returnTopIfAbsent"] = returnTopIfAbsent
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresListWindowCall) Fields(s ...googleapi.Field) *ScoresListWindowCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ScoresListWindowCall) IfNoneMatch(entityTag string) *ScoresListWindowCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresListWindowCall) Context(ctx context.Context) *ScoresListWindowCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresListWindowCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("timeSpan", fmt.Sprintf("%v", c.timeSpan))
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["resultsAbove"]; ok {
		params.Set("resultsAbove", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["returnTopIfAbsent"]; ok {
		params.Set("returnTopIfAbsent", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}/window/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
		"collection":    c.collection,
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

// Do executes the "games.scores.listWindow" call.
// Exactly one of *LeaderboardScores or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *LeaderboardScores.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresListWindowCall) Do() (*LeaderboardScores, error) {
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
	ret := &LeaderboardScores{
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
	//   "description": "Lists the scores in a leaderboard around (and including) a player's score.",
	//   "httpMethod": "GET",
	//   "id": "games.scores.listWindow",
	//   "parameterOrder": [
	//     "leaderboardId",
	//     "collection",
	//     "timeSpan"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "The collection of scores you're requesting.",
	//       "enum": [
	//         "PUBLIC",
	//         "SOCIAL"
	//       ],
	//       "enumDescriptions": [
	//         "List all scores in the public leaderboard.",
	//         "List only social scores."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of leaderboard scores to return in the response. For any response, the actual number of leaderboard scores returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "30",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "resultsAbove": {
	//       "description": "The preferred number of scores to return above the player's score. More scores may be returned if the player is at the bottom of the leaderboard; fewer may be returned if the player is at the top. Must be less than or equal to maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "returnTopIfAbsent": {
	//       "description": "True if the top scores should be returned when the player is not in the leaderboard. Defaults to true.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "timeSpan": {
	//       "description": "The time span for the scores and ranks you're requesting.",
	//       "enum": [
	//         "ALL_TIME",
	//         "DAILY",
	//         "WEEKLY"
	//       ],
	//       "enumDescriptions": [
	//         "List the all-time top scores.",
	//         "List the top scores for the current day.",
	//         "List the top scores for the current week."
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}/window/{collection}",
	//   "response": {
	//     "$ref": "LeaderboardScores"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.scores.submit":

type ScoresSubmitCall struct {
	s             *Service
	leaderboardId string
	score         int64
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Submit: Submits a score to the specified leaderboard.
func (r *ScoresService) Submit(leaderboardId string, score int64) *ScoresSubmitCall {
	c := &ScoresSubmitCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	c.score = score
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ScoresSubmitCall) Language(language string) *ScoresSubmitCall {
	c.opt_["language"] = language
	return c
}

// ScoreTag sets the optional parameter "scoreTag": Additional
// information about the score you're submitting. Values must contain no
// more than 64 URI-safe characters as defined by section 2.3 of RFC
// 3986.
func (c *ScoresSubmitCall) ScoreTag(scoreTag string) *ScoresSubmitCall {
	c.opt_["scoreTag"] = scoreTag
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresSubmitCall) Fields(s ...googleapi.Field) *ScoresSubmitCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresSubmitCall) Context(ctx context.Context) *ScoresSubmitCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresSubmitCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("score", fmt.Sprintf("%v", c.score))
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["scoreTag"]; ok {
		params.Set("scoreTag", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}/scores")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.scores.submit" call.
// Exactly one of *PlayerScoreResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *PlayerScoreResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresSubmitCall) Do() (*PlayerScoreResponse, error) {
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
	ret := &PlayerScoreResponse{
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
	//   "description": "Submits a score to the specified leaderboard.",
	//   "httpMethod": "POST",
	//   "id": "games.scores.submit",
	//   "parameterOrder": [
	//     "leaderboardId",
	//     "score"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "score": {
	//       "description": "The score you're submitting. The submitted score is ignored if it is worse than a previously submitted score, where worse depends on the leaderboard sort order. The meaning of the score value depends on the leaderboard format type. For fixed-point, the score represents the raw value. For time, the score represents elapsed time in milliseconds. For currency, the score represents a value in micro units.",
	//       "format": "int64",
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "scoreTag": {
	//       "description": "Additional information about the score you're submitting. Values must contain no more than 64 URI-safe characters as defined by section 2.3 of RFC 3986.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z0-9-._~]{0,64}",
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}/scores",
	//   "response": {
	//     "$ref": "PlayerScoreResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.scores.submitMultiple":

type ScoresSubmitMultipleCall struct {
	s                         *Service
	playerscoresubmissionlist *PlayerScoreSubmissionList
	opt_                      map[string]interface{}
	ctx_                      context.Context
}

// SubmitMultiple: Submits multiple scores to leaderboards.
func (r *ScoresService) SubmitMultiple(playerscoresubmissionlist *PlayerScoreSubmissionList) *ScoresSubmitMultipleCall {
	c := &ScoresSubmitMultipleCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerscoresubmissionlist = playerscoresubmissionlist
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *ScoresSubmitMultipleCall) Language(language string) *ScoresSubmitMultipleCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresSubmitMultipleCall) Fields(s ...googleapi.Field) *ScoresSubmitMultipleCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresSubmitMultipleCall) Context(ctx context.Context) *ScoresSubmitMultipleCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresSubmitMultipleCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.playerscoresubmissionlist)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/scores")
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

// Do executes the "games.scores.submitMultiple" call.
// Exactly one of *PlayerScoreListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *PlayerScoreListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresSubmitMultipleCall) Do() (*PlayerScoreListResponse, error) {
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
	ret := &PlayerScoreListResponse{
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
	//   "description": "Submits multiple scores to leaderboards.",
	//   "httpMethod": "POST",
	//   "id": "games.scores.submitMultiple",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/scores",
	//   "request": {
	//     "$ref": "PlayerScoreSubmissionList"
	//   },
	//   "response": {
	//     "$ref": "PlayerScoreListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.snapshots.get":

type SnapshotsGetCall struct {
	s          *Service
	snapshotId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Get: Retrieves the metadata for a given snapshot ID.
func (r *SnapshotsService) Get(snapshotId string) *SnapshotsGetCall {
	c := &SnapshotsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.snapshotId = snapshotId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *SnapshotsGetCall) Language(language string) *SnapshotsGetCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SnapshotsGetCall) Fields(s ...googleapi.Field) *SnapshotsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SnapshotsGetCall) IfNoneMatch(entityTag string) *SnapshotsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SnapshotsGetCall) Context(ctx context.Context) *SnapshotsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *SnapshotsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "snapshots/{snapshotId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"snapshotId": c.snapshotId,
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

// Do executes the "games.snapshots.get" call.
// Exactly one of *Snapshot or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Snapshot.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *SnapshotsGetCall) Do() (*Snapshot, error) {
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
	ret := &Snapshot{
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
	//   "description": "Retrieves the metadata for a given snapshot ID.",
	//   "httpMethod": "GET",
	//   "id": "games.snapshots.get",
	//   "parameterOrder": [
	//     "snapshotId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "snapshotId": {
	//       "description": "The ID of the snapshot.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "snapshots/{snapshotId}",
	//   "response": {
	//     "$ref": "Snapshot"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.snapshots.list":

type SnapshotsListCall struct {
	s        *Service
	playerId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// List: Retrieves a list of snapshots created by your application for
// the player corresponding to the player ID.
func (r *SnapshotsService) List(playerId string) *SnapshotsListCall {
	c := &SnapshotsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.playerId = playerId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *SnapshotsListCall) Language(language string) *SnapshotsListCall {
	c.opt_["language"] = language
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of snapshot resources to return in the response, used for
// paging. For any response, the actual number of snapshot resources
// returned may be less than the specified maxResults.
func (c *SnapshotsListCall) MaxResults(maxResults int64) *SnapshotsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *SnapshotsListCall) PageToken(pageToken string) *SnapshotsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SnapshotsListCall) Fields(s ...googleapi.Field) *SnapshotsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SnapshotsListCall) IfNoneMatch(entityTag string) *SnapshotsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SnapshotsListCall) Context(ctx context.Context) *SnapshotsListCall {
	c.ctx_ = ctx
	return c
}

func (c *SnapshotsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "players/{playerId}/snapshots")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"playerId": c.playerId,
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

// Do executes the "games.snapshots.list" call.
// Exactly one of *SnapshotListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SnapshotListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SnapshotsListCall) Do() (*SnapshotListResponse, error) {
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
	ret := &SnapshotListResponse{
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
	//   "description": "Retrieves a list of snapshots created by your application for the player corresponding to the player ID.",
	//   "httpMethod": "GET",
	//   "id": "games.snapshots.list",
	//   "parameterOrder": [
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of snapshot resources to return in the response, used for paging. For any response, the actual number of snapshot resources returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "25",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "players/{playerId}/snapshots",
	//   "response": {
	//     "$ref": "SnapshotListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.cancel":

type TurnBasedMatchesCancelCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Cancel: Cancel a turn-based match.
func (r *TurnBasedMatchesService) Cancel(matchId string) *TurnBasedMatchesCancelCall {
	c := &TurnBasedMatchesCancelCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesCancelCall) Fields(s ...googleapi.Field) *TurnBasedMatchesCancelCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesCancelCall) Context(ctx context.Context) *TurnBasedMatchesCancelCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesCancelCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/cancel")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.cancel" call.
func (c *TurnBasedMatchesCancelCall) Do() error {
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
	//   "description": "Cancel a turn-based match.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.cancel",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/cancel",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.create":

type TurnBasedMatchesCreateCall struct {
	s                           *Service
	turnbasedmatchcreaterequest *TurnBasedMatchCreateRequest
	opt_                        map[string]interface{}
	ctx_                        context.Context
}

// Create: Create a turn-based match.
func (r *TurnBasedMatchesService) Create(turnbasedmatchcreaterequest *TurnBasedMatchCreateRequest) *TurnBasedMatchesCreateCall {
	c := &TurnBasedMatchesCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.turnbasedmatchcreaterequest = turnbasedmatchcreaterequest
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesCreateCall) Language(language string) *TurnBasedMatchesCreateCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesCreateCall) Fields(s ...googleapi.Field) *TurnBasedMatchesCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesCreateCall) Context(ctx context.Context) *TurnBasedMatchesCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.turnbasedmatchcreaterequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/create")
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

// Do executes the "games.turnBasedMatches.create" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesCreateCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Create a turn-based match.",
	//   "httpMethod": "POST",
	//   "id": "games.turnBasedMatches.create",
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/create",
	//   "request": {
	//     "$ref": "TurnBasedMatchCreateRequest"
	//   },
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.decline":

type TurnBasedMatchesDeclineCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Decline: Decline an invitation to play a turn-based match.
func (r *TurnBasedMatchesService) Decline(matchId string) *TurnBasedMatchesDeclineCall {
	c := &TurnBasedMatchesDeclineCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesDeclineCall) Language(language string) *TurnBasedMatchesDeclineCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesDeclineCall) Fields(s ...googleapi.Field) *TurnBasedMatchesDeclineCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesDeclineCall) Context(ctx context.Context) *TurnBasedMatchesDeclineCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesDeclineCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/decline")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.decline" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesDeclineCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Decline an invitation to play a turn-based match.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.decline",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/decline",
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.dismiss":

type TurnBasedMatchesDismissCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Dismiss: Dismiss a turn-based match from the match list. The match
// will no longer show up in the list and will not generate
// notifications.
func (r *TurnBasedMatchesService) Dismiss(matchId string) *TurnBasedMatchesDismissCall {
	c := &TurnBasedMatchesDismissCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesDismissCall) Fields(s ...googleapi.Field) *TurnBasedMatchesDismissCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesDismissCall) Context(ctx context.Context) *TurnBasedMatchesDismissCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesDismissCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/dismiss")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.dismiss" call.
func (c *TurnBasedMatchesDismissCall) Do() error {
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
	//   "description": "Dismiss a turn-based match from the match list. The match will no longer show up in the list and will not generate notifications.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.dismiss",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/dismiss",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.finish":

type TurnBasedMatchesFinishCall struct {
	s                     *Service
	matchId               string
	turnbasedmatchresults *TurnBasedMatchResults
	opt_                  map[string]interface{}
	ctx_                  context.Context
}

// Finish: Finish a turn-based match. Each player should make this call
// once, after all results are in. Only the player whose turn it is may
// make the first call to Finish, and can pass in the final match state.
func (r *TurnBasedMatchesService) Finish(matchId string, turnbasedmatchresults *TurnBasedMatchResults) *TurnBasedMatchesFinishCall {
	c := &TurnBasedMatchesFinishCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	c.turnbasedmatchresults = turnbasedmatchresults
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesFinishCall) Language(language string) *TurnBasedMatchesFinishCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesFinishCall) Fields(s ...googleapi.Field) *TurnBasedMatchesFinishCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesFinishCall) Context(ctx context.Context) *TurnBasedMatchesFinishCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesFinishCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.turnbasedmatchresults)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/finish")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.finish" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesFinishCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Finish a turn-based match. Each player should make this call once, after all results are in. Only the player whose turn it is may make the first call to Finish, and can pass in the final match state.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.finish",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/finish",
	//   "request": {
	//     "$ref": "TurnBasedMatchResults"
	//   },
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.get":

type TurnBasedMatchesGetCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Get: Get the data for a turn-based match.
func (r *TurnBasedMatchesService) Get(matchId string) *TurnBasedMatchesGetCall {
	c := &TurnBasedMatchesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// IncludeMatchData sets the optional parameter "includeMatchData": Get
// match data along with metadata.
func (c *TurnBasedMatchesGetCall) IncludeMatchData(includeMatchData bool) *TurnBasedMatchesGetCall {
	c.opt_["includeMatchData"] = includeMatchData
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesGetCall) Language(language string) *TurnBasedMatchesGetCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesGetCall) Fields(s ...googleapi.Field) *TurnBasedMatchesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *TurnBasedMatchesGetCall) IfNoneMatch(entityTag string) *TurnBasedMatchesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesGetCall) Context(ctx context.Context) *TurnBasedMatchesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeMatchData"]; ok {
		params.Set("includeMatchData", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
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

// Do executes the "games.turnBasedMatches.get" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesGetCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Get the data for a turn-based match.",
	//   "httpMethod": "GET",
	//   "id": "games.turnBasedMatches.get",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "includeMatchData": {
	//       "description": "Get match data along with metadata.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}",
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.join":

type TurnBasedMatchesJoinCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Join: Join a turn-based match.
func (r *TurnBasedMatchesService) Join(matchId string) *TurnBasedMatchesJoinCall {
	c := &TurnBasedMatchesJoinCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesJoinCall) Language(language string) *TurnBasedMatchesJoinCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesJoinCall) Fields(s ...googleapi.Field) *TurnBasedMatchesJoinCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesJoinCall) Context(ctx context.Context) *TurnBasedMatchesJoinCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesJoinCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/join")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.join" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesJoinCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Join a turn-based match.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.join",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/join",
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.leave":

type TurnBasedMatchesLeaveCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Leave: Leave a turn-based match when it is not the current player's
// turn, without canceling the match.
func (r *TurnBasedMatchesService) Leave(matchId string) *TurnBasedMatchesLeaveCall {
	c := &TurnBasedMatchesLeaveCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesLeaveCall) Language(language string) *TurnBasedMatchesLeaveCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesLeaveCall) Fields(s ...googleapi.Field) *TurnBasedMatchesLeaveCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesLeaveCall) Context(ctx context.Context) *TurnBasedMatchesLeaveCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesLeaveCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/leave")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.leave" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesLeaveCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Leave a turn-based match when it is not the current player's turn, without canceling the match.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.leave",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/leave",
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.leaveTurn":

type TurnBasedMatchesLeaveTurnCall struct {
	s            *Service
	matchId      string
	matchVersion int64
	opt_         map[string]interface{}
	ctx_         context.Context
}

// LeaveTurn: Leave a turn-based match during the current player's turn,
// without canceling the match.
func (r *TurnBasedMatchesService) LeaveTurn(matchId string, matchVersion int64) *TurnBasedMatchesLeaveTurnCall {
	c := &TurnBasedMatchesLeaveTurnCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	c.matchVersion = matchVersion
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesLeaveTurnCall) Language(language string) *TurnBasedMatchesLeaveTurnCall {
	c.opt_["language"] = language
	return c
}

// PendingParticipantId sets the optional parameter
// "pendingParticipantId": The ID of another participant who should take
// their turn next. If not set, the match will wait for other player(s)
// to join via automatching; this is only valid if automatch criteria is
// set on the match with remaining slots for automatched players.
func (c *TurnBasedMatchesLeaveTurnCall) PendingParticipantId(pendingParticipantId string) *TurnBasedMatchesLeaveTurnCall {
	c.opt_["pendingParticipantId"] = pendingParticipantId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesLeaveTurnCall) Fields(s ...googleapi.Field) *TurnBasedMatchesLeaveTurnCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesLeaveTurnCall) Context(ctx context.Context) *TurnBasedMatchesLeaveTurnCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesLeaveTurnCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("matchVersion", fmt.Sprintf("%v", c.matchVersion))
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pendingParticipantId"]; ok {
		params.Set("pendingParticipantId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/leaveTurn")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.leaveTurn" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesLeaveTurnCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Leave a turn-based match during the current player's turn, without canceling the match.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.leaveTurn",
	//   "parameterOrder": [
	//     "matchId",
	//     "matchVersion"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "matchVersion": {
	//       "description": "The version of the match being updated.",
	//       "format": "int32",
	//       "location": "query",
	//       "required": true,
	//       "type": "integer"
	//     },
	//     "pendingParticipantId": {
	//       "description": "The ID of another participant who should take their turn next. If not set, the match will wait for other player(s) to join via automatching; this is only valid if automatch criteria is set on the match with remaining slots for automatched players.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/leaveTurn",
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.list":

type TurnBasedMatchesListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Returns turn-based matches the player is or was involved in.
func (r *TurnBasedMatchesService) List() *TurnBasedMatchesListCall {
	c := &TurnBasedMatchesListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// IncludeMatchData sets the optional parameter "includeMatchData": True
// if match data should be returned in the response. Note that not all
// data will necessarily be returned if include_match_data is true; the
// server may decide to only return data for some of the matches to
// limit download size for the client. The remainder of the data for
// these matches will be retrievable on request.
func (c *TurnBasedMatchesListCall) IncludeMatchData(includeMatchData bool) *TurnBasedMatchesListCall {
	c.opt_["includeMatchData"] = includeMatchData
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesListCall) Language(language string) *TurnBasedMatchesListCall {
	c.opt_["language"] = language
	return c
}

// MaxCompletedMatches sets the optional parameter
// "maxCompletedMatches": The maximum number of completed or canceled
// matches to return in the response. If not set, all matches returned
// could be completed or canceled.
func (c *TurnBasedMatchesListCall) MaxCompletedMatches(maxCompletedMatches int64) *TurnBasedMatchesListCall {
	c.opt_["maxCompletedMatches"] = maxCompletedMatches
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of matches to return in the response, used for paging. For any
// response, the actual number of matches to return may be less than the
// specified maxResults.
func (c *TurnBasedMatchesListCall) MaxResults(maxResults int64) *TurnBasedMatchesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *TurnBasedMatchesListCall) PageToken(pageToken string) *TurnBasedMatchesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesListCall) Fields(s ...googleapi.Field) *TurnBasedMatchesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *TurnBasedMatchesListCall) IfNoneMatch(entityTag string) *TurnBasedMatchesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesListCall) Context(ctx context.Context) *TurnBasedMatchesListCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeMatchData"]; ok {
		params.Set("includeMatchData", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxCompletedMatches"]; ok {
		params.Set("maxCompletedMatches", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches")
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

// Do executes the "games.turnBasedMatches.list" call.
// Exactly one of *TurnBasedMatchList or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *TurnBasedMatchList.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesListCall) Do() (*TurnBasedMatchList, error) {
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
	ret := &TurnBasedMatchList{
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
	//   "description": "Returns turn-based matches the player is or was involved in.",
	//   "httpMethod": "GET",
	//   "id": "games.turnBasedMatches.list",
	//   "parameters": {
	//     "includeMatchData": {
	//       "description": "True if match data should be returned in the response. Note that not all data will necessarily be returned if include_match_data is true; the server may decide to only return data for some of the matches to limit download size for the client. The remainder of the data for these matches will be retrievable on request.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxCompletedMatches": {
	//       "description": "The maximum number of completed or canceled matches to return in the response. If not set, all matches returned could be completed or canceled.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of matches to return in the response, used for paging. For any response, the actual number of matches to return may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches",
	//   "response": {
	//     "$ref": "TurnBasedMatchList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.rematch":

type TurnBasedMatchesRematchCall struct {
	s       *Service
	matchId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Rematch: Create a rematch of a match that was previously completed,
// with the same participants. This can be called by only one player on
// a match still in their list; the player must have called Finish
// first. Returns the newly created match; it will be the caller's turn.
func (r *TurnBasedMatchesService) Rematch(matchId string) *TurnBasedMatchesRematchCall {
	c := &TurnBasedMatchesRematchCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesRematchCall) Language(language string) *TurnBasedMatchesRematchCall {
	c.opt_["language"] = language
	return c
}

// RequestId sets the optional parameter "requestId": A randomly
// generated numeric ID for each request specified by the caller. This
// number is used at the server to ensure that the request is handled
// correctly across retries.
func (c *TurnBasedMatchesRematchCall) RequestId(requestId int64) *TurnBasedMatchesRematchCall {
	c.opt_["requestId"] = requestId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesRematchCall) Fields(s ...googleapi.Field) *TurnBasedMatchesRematchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesRematchCall) Context(ctx context.Context) *TurnBasedMatchesRematchCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesRematchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["requestId"]; ok {
		params.Set("requestId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/rematch")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.rematch" call.
// Exactly one of *TurnBasedMatchRematch or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *TurnBasedMatchRematch.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesRematchCall) Do() (*TurnBasedMatchRematch, error) {
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
	ret := &TurnBasedMatchRematch{
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
	//   "description": "Create a rematch of a match that was previously completed, with the same participants. This can be called by only one player on a match still in their list; the player must have called Finish first. Returns the newly created match; it will be the caller's turn.",
	//   "httpMethod": "POST",
	//   "id": "games.turnBasedMatches.rematch",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "requestId": {
	//       "description": "A randomly generated numeric ID for each request specified by the caller. This number is used at the server to ensure that the request is handled correctly across retries.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/rematch",
	//   "response": {
	//     "$ref": "TurnBasedMatchRematch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.sync":

type TurnBasedMatchesSyncCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Sync: Returns turn-based matches the player is or was involved in
// that changed since the last sync call, with the least recent changes
// coming first. Matches that should be removed from the local cache
// will have a status of MATCH_DELETED.
func (r *TurnBasedMatchesService) Sync() *TurnBasedMatchesSyncCall {
	c := &TurnBasedMatchesSyncCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// IncludeMatchData sets the optional parameter "includeMatchData": True
// if match data should be returned in the response. Note that not all
// data will necessarily be returned if include_match_data is true; the
// server may decide to only return data for some of the matches to
// limit download size for the client. The remainder of the data for
// these matches will be retrievable on request.
func (c *TurnBasedMatchesSyncCall) IncludeMatchData(includeMatchData bool) *TurnBasedMatchesSyncCall {
	c.opt_["includeMatchData"] = includeMatchData
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesSyncCall) Language(language string) *TurnBasedMatchesSyncCall {
	c.opt_["language"] = language
	return c
}

// MaxCompletedMatches sets the optional parameter
// "maxCompletedMatches": The maximum number of completed or canceled
// matches to return in the response. If not set, all matches returned
// could be completed or canceled.
func (c *TurnBasedMatchesSyncCall) MaxCompletedMatches(maxCompletedMatches int64) *TurnBasedMatchesSyncCall {
	c.opt_["maxCompletedMatches"] = maxCompletedMatches
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of matches to return in the response, used for paging. For any
// response, the actual number of matches to return may be less than the
// specified maxResults.
func (c *TurnBasedMatchesSyncCall) MaxResults(maxResults int64) *TurnBasedMatchesSyncCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *TurnBasedMatchesSyncCall) PageToken(pageToken string) *TurnBasedMatchesSyncCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesSyncCall) Fields(s ...googleapi.Field) *TurnBasedMatchesSyncCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *TurnBasedMatchesSyncCall) IfNoneMatch(entityTag string) *TurnBasedMatchesSyncCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesSyncCall) Context(ctx context.Context) *TurnBasedMatchesSyncCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesSyncCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeMatchData"]; ok {
		params.Set("includeMatchData", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxCompletedMatches"]; ok {
		params.Set("maxCompletedMatches", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/sync")
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

// Do executes the "games.turnBasedMatches.sync" call.
// Exactly one of *TurnBasedMatchSync or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *TurnBasedMatchSync.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesSyncCall) Do() (*TurnBasedMatchSync, error) {
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
	ret := &TurnBasedMatchSync{
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
	//   "description": "Returns turn-based matches the player is or was involved in that changed since the last sync call, with the least recent changes coming first. Matches that should be removed from the local cache will have a status of MATCH_DELETED.",
	//   "httpMethod": "GET",
	//   "id": "games.turnBasedMatches.sync",
	//   "parameters": {
	//     "includeMatchData": {
	//       "description": "True if match data should be returned in the response. Note that not all data will necessarily be returned if include_match_data is true; the server may decide to only return data for some of the matches to limit download size for the client. The remainder of the data for these matches will be retrievable on request.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxCompletedMatches": {
	//       "description": "The maximum number of completed or canceled matches to return in the response. If not set, all matches returned could be completed or canceled.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of matches to return in the response, used for paging. For any response, the actual number of matches to return may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/sync",
	//   "response": {
	//     "$ref": "TurnBasedMatchSync"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "games.turnBasedMatches.takeTurn":

type TurnBasedMatchesTakeTurnCall struct {
	s                  *Service
	matchId            string
	turnbasedmatchturn *TurnBasedMatchTurn
	opt_               map[string]interface{}
	ctx_               context.Context
}

// TakeTurn: Commit the results of a player turn.
func (r *TurnBasedMatchesService) TakeTurn(matchId string, turnbasedmatchturn *TurnBasedMatchTurn) *TurnBasedMatchesTakeTurnCall {
	c := &TurnBasedMatchesTakeTurnCall{s: r.s, opt_: make(map[string]interface{})}
	c.matchId = matchId
	c.turnbasedmatchturn = turnbasedmatchturn
	return c
}

// Language sets the optional parameter "language": The preferred
// language to use for strings returned by this method.
func (c *TurnBasedMatchesTakeTurnCall) Language(language string) *TurnBasedMatchesTakeTurnCall {
	c.opt_["language"] = language
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesTakeTurnCall) Fields(s ...googleapi.Field) *TurnBasedMatchesTakeTurnCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesTakeTurnCall) Context(ctx context.Context) *TurnBasedMatchesTakeTurnCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesTakeTurnCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.turnbasedmatchturn)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["language"]; ok {
		params.Set("language", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/{matchId}/turn")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"matchId": c.matchId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "games.turnBasedMatches.takeTurn" call.
// Exactly one of *TurnBasedMatch or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TurnBasedMatch.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *TurnBasedMatchesTakeTurnCall) Do() (*TurnBasedMatch, error) {
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
	ret := &TurnBasedMatch{
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
	//   "description": "Commit the results of a player turn.",
	//   "httpMethod": "PUT",
	//   "id": "games.turnBasedMatches.takeTurn",
	//   "parameterOrder": [
	//     "matchId"
	//   ],
	//   "parameters": {
	//     "language": {
	//       "description": "The preferred language to use for strings returned by this method.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "matchId": {
	//       "description": "The ID of the match.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "turnbasedmatches/{matchId}/turn",
	//   "request": {
	//     "$ref": "TurnBasedMatchTurn"
	//   },
	//   "response": {
	//     "$ref": "TurnBasedMatch"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}
