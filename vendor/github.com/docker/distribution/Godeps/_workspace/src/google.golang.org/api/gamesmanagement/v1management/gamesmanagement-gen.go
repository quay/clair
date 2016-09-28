// Package gamesmanagement provides access to the Google Play Game Services Management API.
//
// See https://developers.google.com/games/services
//
// Usage example:
//
//   import "google.golang.org/api/gamesmanagement/v1management"
//   ...
//   gamesmanagementService, err := gamesmanagement.New(oauthHttpClient)
package gamesmanagement // import "google.golang.org/api/gamesmanagement/v1management"

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

const apiId = "gamesManagement:v1management"
const apiName = "gamesManagement"
const apiVersion = "v1management"
const basePath = "https://www.googleapis.com/games/v1management/"

// OAuth2 scopes used by this API.
const (
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
	s.Achievements = NewAchievementsService(s)
	s.Applications = NewApplicationsService(s)
	s.Events = NewEventsService(s)
	s.Players = NewPlayersService(s)
	s.Quests = NewQuestsService(s)
	s.Rooms = NewRoomsService(s)
	s.Scores = NewScoresService(s)
	s.TurnBasedMatches = NewTurnBasedMatchesService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Achievements *AchievementsService

	Applications *ApplicationsService

	Events *EventsService

	Players *PlayersService

	Quests *QuestsService

	Rooms *RoomsService

	Scores *ScoresService

	TurnBasedMatches *TurnBasedMatchesService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
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

func NewPlayersService(s *Service) *PlayersService {
	rs := &PlayersService{s: s}
	return rs
}

type PlayersService struct {
	s *Service
}

func NewQuestsService(s *Service) *QuestsService {
	rs := &QuestsService{s: s}
	return rs
}

type QuestsService struct {
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

func NewTurnBasedMatchesService(s *Service) *TurnBasedMatchesService {
	rs := &TurnBasedMatchesService{s: s}
	return rs
}

type TurnBasedMatchesService struct {
	s *Service
}

// AchievementResetAllResponse: This is a JSON template for achievement
// reset all response.
type AchievementResetAllResponse struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#achievementResetAllResponse.
	Kind string `json:"kind,omitempty"`

	// Results: The achievement reset results.
	Results []*AchievementResetResponse `json:"results,omitempty"`

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

func (s *AchievementResetAllResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementResetAllResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementResetMultipleForAllRequest: This is a JSON template for
// multiple achievements reset all request.
type AchievementResetMultipleForAllRequest struct {
	// AchievementIds: The IDs of achievements to reset.
	AchievementIds []string `json:"achievement_ids,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string
	// gamesManagement#achievementResetMultipleForAllRequest.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AchievementIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementResetMultipleForAllRequest) MarshalJSON() ([]byte, error) {
	type noMethod AchievementResetMultipleForAllRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementResetResponse: This is a JSON template for an achievement
// reset response.
type AchievementResetResponse struct {
	// CurrentState: The current state of the achievement. This is the same
	// as the initial state of the achievement.
	// Possible values are:
	// - "HIDDEN"- Achievement is hidden.
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	CurrentState string `json:"currentState,omitempty"`

	// DefinitionId: The ID of an achievement for which player state has
	// been updated.
	DefinitionId string `json:"definitionId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#achievementResetResponse.
	Kind string `json:"kind,omitempty"`

	// UpdateOccurred: Flag to indicate if the requested update actually
	// occurred.
	UpdateOccurred bool `json:"updateOccurred,omitempty"`

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

func (s *AchievementResetResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementResetResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EventsResetMultipleForAllRequest: This is a JSON template for
// multiple events reset all request.
type EventsResetMultipleForAllRequest struct {
	// EventIds: The IDs of events to reset.
	EventIds []string `json:"event_ids,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#eventsResetMultipleForAllRequest.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EventIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EventsResetMultipleForAllRequest) MarshalJSON() ([]byte, error) {
	type noMethod EventsResetMultipleForAllRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesPlayedResource: This is a JSON template for metadata about a
// player playing a game with the currently authenticated user.
type GamesPlayedResource struct {
	// AutoMatched: True if the player was auto-matched with the currently
	// authenticated user.
	AutoMatched bool `json:"autoMatched,omitempty"`

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

func (s *GamesPlayedResource) MarshalJSON() ([]byte, error) {
	type noMethod GamesPlayedResource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesPlayerExperienceInfoResource: This is a JSON template for 1P/3P
// metadata about the player's experience.
type GamesPlayerExperienceInfoResource struct {
	// CurrentExperiencePoints: The current number of experience points for
	// the player.
	CurrentExperiencePoints int64 `json:"currentExperiencePoints,omitempty,string"`

	// CurrentLevel: The current level of the player.
	CurrentLevel *GamesPlayerLevelResource `json:"currentLevel,omitempty"`

	// LastLevelUpTimestampMillis: The timestamp when the player was leveled
	// up, in millis since Unix epoch UTC.
	LastLevelUpTimestampMillis int64 `json:"lastLevelUpTimestampMillis,omitempty,string"`

	// NextLevel: The next level of the player. If the current level is the
	// maximum level, this should be same as the current level.
	NextLevel *GamesPlayerLevelResource `json:"nextLevel,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CurrentExperiencePoints") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesPlayerExperienceInfoResource) MarshalJSON() ([]byte, error) {
	type noMethod GamesPlayerExperienceInfoResource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesPlayerLevelResource: This is a JSON template for 1P/3P metadata
// about a user's level.
type GamesPlayerLevelResource struct {
	// Level: The level for the user.
	Level int64 `json:"level,omitempty"`

	// MaxExperiencePoints: The maximum experience points for this level.
	MaxExperiencePoints int64 `json:"maxExperiencePoints,omitempty,string"`

	// MinExperiencePoints: The minimum experience points for this level.
	MinExperiencePoints int64 `json:"minExperiencePoints,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "Level") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesPlayerLevelResource) MarshalJSON() ([]byte, error) {
	type noMethod GamesPlayerLevelResource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// HiddenPlayer: This is a JSON template for the HiddenPlayer resource.
type HiddenPlayer struct {
	// HiddenTimeMillis: The time this player was hidden.
	HiddenTimeMillis int64 `json:"hiddenTimeMillis,omitempty,string"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#hiddenPlayer.
	Kind string `json:"kind,omitempty"`

	// Player: The player information.
	Player *Player `json:"player,omitempty"`

	// ForceSendFields is a list of field names (e.g. "HiddenTimeMillis") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *HiddenPlayer) MarshalJSON() ([]byte, error) {
	type noMethod HiddenPlayer
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// HiddenPlayerList: This is a JSON template for a list of hidden
// players.
type HiddenPlayerList struct {
	// Items: The players.
	Items []*HiddenPlayer `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#hiddenPlayerList.
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

func (s *HiddenPlayerList) MarshalJSON() ([]byte, error) {
	type noMethod HiddenPlayerList
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
	ExperienceInfo *GamesPlayerExperienceInfoResource `json:"experienceInfo,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#player.
	Kind string `json:"kind,omitempty"`

	// LastPlayedWith: Details about the last time this player played a
	// multiplayer game with the currently authenticated player. Populated
	// for PLAYED_WITH player collection members.
	LastPlayedWith *GamesPlayedResource `json:"lastPlayedWith,omitempty"`

	// Name: An object representation of the individual components of the
	// player's name. For some players, these fields may not be present.
	Name *PlayerName `json:"name,omitempty"`

	// PlayerId: The ID of the player.
	PlayerId string `json:"playerId,omitempty"`

	// Title: The player's title rewarded for their game activities.
	Title string `json:"title,omitempty"`

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

// PlayerScoreResetAllResponse: This is a JSON template for a list of
// leaderboard reset resources.
type PlayerScoreResetAllResponse struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#playerScoreResetResponse.
	Kind string `json:"kind,omitempty"`

	// Results: The leaderboard reset results.
	Results []*PlayerScoreResetResponse `json:"results,omitempty"`

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

func (s *PlayerScoreResetAllResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScoreResetAllResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlayerScoreResetResponse: This is a JSON template for a list of reset
// leaderboard entry resources.
type PlayerScoreResetResponse struct {
	// DefinitionId: The ID of an leaderboard for which player state has
	// been updated.
	DefinitionId string `json:"definitionId,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#playerScoreResetResponse.
	Kind string `json:"kind,omitempty"`

	// ResetScoreTimeSpans: The time spans of the updated score.
	// Possible values are:
	// - "ALL_TIME" - The score is an all-time score.
	// - "WEEKLY" - The score is a weekly score.
	// - "DAILY" - The score is a daily score.
	ResetScoreTimeSpans []string `json:"resetScoreTimeSpans,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DefinitionId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlayerScoreResetResponse) MarshalJSON() ([]byte, error) {
	type noMethod PlayerScoreResetResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QuestsResetMultipleForAllRequest: This is a JSON template for
// multiple quests reset all request.
type QuestsResetMultipleForAllRequest struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#questsResetMultipleForAllRequest.
	Kind string `json:"kind,omitempty"`

	// QuestIds: The IDs of quests to reset.
	QuestIds []string `json:"quest_ids,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *QuestsResetMultipleForAllRequest) MarshalJSON() ([]byte, error) {
	type noMethod QuestsResetMultipleForAllRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ScoresResetMultipleForAllRequest: This is a JSON template for
// multiple scores reset all request.
type ScoresResetMultipleForAllRequest struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesManagement#scoresResetMultipleForAllRequest.
	Kind string `json:"kind,omitempty"`

	// LeaderboardIds: The IDs of leaderboards to reset.
	LeaderboardIds []string `json:"leaderboard_ids,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ScoresResetMultipleForAllRequest) MarshalJSON() ([]byte, error) {
	type noMethod ScoresResetMultipleForAllRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "gamesManagement.achievements.reset":

type AchievementsResetCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Reset: Resets the achievement with the given ID for the currently
// authenticated player. This method is only accessible to whitelisted
// tester accounts for your application.
func (r *AchievementsService) Reset(achievementId string) *AchievementsResetCall {
	c := &AchievementsResetCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsResetCall) Fields(s ...googleapi.Field) *AchievementsResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsResetCall) Context(ctx context.Context) *AchievementsResetCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/reset")
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

// Do executes the "gamesManagement.achievements.reset" call.
// Exactly one of *AchievementResetResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementResetResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsResetCall) Do() (*AchievementResetResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AchievementResetResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Resets the achievement with the given ID for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.achievements.reset",
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
	//   "path": "achievements/{achievementId}/reset",
	//   "response": {
	//     "$ref": "AchievementResetResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.achievements.resetAll":

type AchievementsResetAllCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAll: Resets all achievements for the currently authenticated
// player for your application. This method is only accessible to
// whitelisted tester accounts for your application.
func (r *AchievementsService) ResetAll() *AchievementsResetAllCall {
	c := &AchievementsResetAllCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsResetAllCall) Fields(s ...googleapi.Field) *AchievementsResetAllCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsResetAllCall) Context(ctx context.Context) *AchievementsResetAllCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsResetAllCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.achievements.resetAll" call.
// Exactly one of *AchievementResetAllResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementResetAllResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementsResetAllCall) Do() (*AchievementResetAllResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AchievementResetAllResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Resets all achievements for the currently authenticated player for your application. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.achievements.resetAll",
	//   "path": "achievements/reset",
	//   "response": {
	//     "$ref": "AchievementResetAllResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.achievements.resetAllForAllPlayers":

type AchievementsResetAllForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAllForAllPlayers: Resets all draft achievements for all players.
// This method is only available to user accounts for your developer
// console.
func (r *AchievementsService) ResetAllForAllPlayers() *AchievementsResetAllForAllPlayersCall {
	c := &AchievementsResetAllForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsResetAllForAllPlayersCall) Fields(s ...googleapi.Field) *AchievementsResetAllForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsResetAllForAllPlayersCall) Context(ctx context.Context) *AchievementsResetAllForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsResetAllForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/resetAllForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.achievements.resetAllForAllPlayers" call.
func (c *AchievementsResetAllForAllPlayersCall) Do() error {
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
	//   "description": "Resets all draft achievements for all players. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.achievements.resetAllForAllPlayers",
	//   "path": "achievements/resetAllForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.achievements.resetForAllPlayers":

type AchievementsResetForAllPlayersCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// ResetForAllPlayers: Resets the achievement with the given ID for all
// players. This method is only available to user accounts for your
// developer console. Only draft achievements can be reset.
func (r *AchievementsService) ResetForAllPlayers(achievementId string) *AchievementsResetForAllPlayersCall {
	c := &AchievementsResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsResetForAllPlayersCall) Fields(s ...googleapi.Field) *AchievementsResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsResetForAllPlayersCall) Context(ctx context.Context) *AchievementsResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}/resetForAllPlayers")
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

// Do executes the "gamesManagement.achievements.resetForAllPlayers" call.
func (c *AchievementsResetForAllPlayersCall) Do() error {
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
	//   "description": "Resets the achievement with the given ID for all players. This method is only available to user accounts for your developer console. Only draft achievements can be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.achievements.resetForAllPlayers",
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
	//   "path": "achievements/{achievementId}/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.achievements.resetMultipleForAllPlayers":

type AchievementsResetMultipleForAllPlayersCall struct {
	s                                     *Service
	achievementresetmultipleforallrequest *AchievementResetMultipleForAllRequest
	opt_                                  map[string]interface{}
	ctx_                                  context.Context
}

// ResetMultipleForAllPlayers: Resets achievements with the given IDs
// for all players. This method is only available to user accounts for
// your developer console. Only draft achievements may be reset.
func (r *AchievementsService) ResetMultipleForAllPlayers(achievementresetmultipleforallrequest *AchievementResetMultipleForAllRequest) *AchievementsResetMultipleForAllPlayersCall {
	c := &AchievementsResetMultipleForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementresetmultipleforallrequest = achievementresetmultipleforallrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementsResetMultipleForAllPlayersCall) Fields(s ...googleapi.Field) *AchievementsResetMultipleForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementsResetMultipleForAllPlayersCall) Context(ctx context.Context) *AchievementsResetMultipleForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementsResetMultipleForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.achievementresetmultipleforallrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/resetMultipleForAllPlayers")
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

// Do executes the "gamesManagement.achievements.resetMultipleForAllPlayers" call.
func (c *AchievementsResetMultipleForAllPlayersCall) Do() error {
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
	//   "description": "Resets achievements with the given IDs for all players. This method is only available to user accounts for your developer console. Only draft achievements may be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.achievements.resetMultipleForAllPlayers",
	//   "path": "achievements/resetMultipleForAllPlayers",
	//   "request": {
	//     "$ref": "AchievementResetMultipleForAllRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.applications.listHidden":

type ApplicationsListHiddenCall struct {
	s             *Service
	applicationId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// ListHidden: Get the list of players hidden from the given
// application. This method is only available to user accounts for your
// developer console.
func (r *ApplicationsService) ListHidden(applicationId string) *ApplicationsListHiddenCall {
	c := &ApplicationsListHiddenCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of player resources to return in the response, used for
// paging. For any response, the actual number of player resources
// returned may be less than the specified maxResults.
func (c *ApplicationsListHiddenCall) MaxResults(maxResults int64) *ApplicationsListHiddenCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *ApplicationsListHiddenCall) PageToken(pageToken string) *ApplicationsListHiddenCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ApplicationsListHiddenCall) Fields(s ...googleapi.Field) *ApplicationsListHiddenCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ApplicationsListHiddenCall) IfNoneMatch(entityTag string) *ApplicationsListHiddenCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ApplicationsListHiddenCall) Context(ctx context.Context) *ApplicationsListHiddenCall {
	c.ctx_ = ctx
	return c
}

func (c *ApplicationsListHiddenCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/players/hidden")
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

// Do executes the "gamesManagement.applications.listHidden" call.
// Exactly one of *HiddenPlayerList or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *HiddenPlayerList.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ApplicationsListHiddenCall) Do() (*HiddenPlayerList, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &HiddenPlayerList{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Get the list of players hidden from the given application. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "GET",
	//   "id": "gamesManagement.applications.listHidden",
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
	//   "path": "applications/{applicationId}/players/hidden",
	//   "response": {
	//     "$ref": "HiddenPlayerList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.events.reset":

type EventsResetCall struct {
	s       *Service
	eventId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Reset: Resets all player progress on the event with the given ID for
// the currently authenticated player. This method is only accessible to
// whitelisted tester accounts for your application. All quests for this
// player that use the event will also be reset.
func (r *EventsService) Reset(eventId string) *EventsResetCall {
	c := &EventsResetCall{s: r.s, opt_: make(map[string]interface{})}
	c.eventId = eventId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsResetCall) Fields(s ...googleapi.Field) *EventsResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsResetCall) Context(ctx context.Context) *EventsResetCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events/{eventId}/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"eventId": c.eventId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.events.reset" call.
func (c *EventsResetCall) Do() error {
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
	//   "description": "Resets all player progress on the event with the given ID for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application. All quests for this player that use the event will also be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.events.reset",
	//   "parameterOrder": [
	//     "eventId"
	//   ],
	//   "parameters": {
	//     "eventId": {
	//       "description": "The ID of the event.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "events/{eventId}/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.events.resetAll":

type EventsResetAllCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAll: Resets all player progress on all events for the currently
// authenticated player. This method is only accessible to whitelisted
// tester accounts for your application. All quests for this player will
// also be reset.
func (r *EventsService) ResetAll() *EventsResetAllCall {
	c := &EventsResetAllCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsResetAllCall) Fields(s ...googleapi.Field) *EventsResetAllCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsResetAllCall) Context(ctx context.Context) *EventsResetAllCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsResetAllCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.events.resetAll" call.
func (c *EventsResetAllCall) Do() error {
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
	//   "description": "Resets all player progress on all events for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application. All quests for this player will also be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.events.resetAll",
	//   "path": "events/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.events.resetAllForAllPlayers":

type EventsResetAllForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAllForAllPlayers: Resets all draft events for all players. This
// method is only available to user accounts for your developer console.
// All quests that use any of these events will also be reset.
func (r *EventsService) ResetAllForAllPlayers() *EventsResetAllForAllPlayersCall {
	c := &EventsResetAllForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsResetAllForAllPlayersCall) Fields(s ...googleapi.Field) *EventsResetAllForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsResetAllForAllPlayersCall) Context(ctx context.Context) *EventsResetAllForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsResetAllForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events/resetAllForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.events.resetAllForAllPlayers" call.
func (c *EventsResetAllForAllPlayersCall) Do() error {
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
	//   "description": "Resets all draft events for all players. This method is only available to user accounts for your developer console. All quests that use any of these events will also be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.events.resetAllForAllPlayers",
	//   "path": "events/resetAllForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.events.resetForAllPlayers":

type EventsResetForAllPlayersCall struct {
	s       *Service
	eventId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// ResetForAllPlayers: Resets the event with the given ID for all
// players. This method is only available to user accounts for your
// developer console. Only draft events can be reset. All quests that
// use the event will also be reset.
func (r *EventsService) ResetForAllPlayers(eventId string) *EventsResetForAllPlayersCall {
	c := &EventsResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.eventId = eventId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsResetForAllPlayersCall) Fields(s ...googleapi.Field) *EventsResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsResetForAllPlayersCall) Context(ctx context.Context) *EventsResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events/{eventId}/resetForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"eventId": c.eventId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.events.resetForAllPlayers" call.
func (c *EventsResetForAllPlayersCall) Do() error {
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
	//   "description": "Resets the event with the given ID for all players. This method is only available to user accounts for your developer console. Only draft events can be reset. All quests that use the event will also be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.events.resetForAllPlayers",
	//   "parameterOrder": [
	//     "eventId"
	//   ],
	//   "parameters": {
	//     "eventId": {
	//       "description": "The ID of the event.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "events/{eventId}/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.events.resetMultipleForAllPlayers":

type EventsResetMultipleForAllPlayersCall struct {
	s                                *Service
	eventsresetmultipleforallrequest *EventsResetMultipleForAllRequest
	opt_                             map[string]interface{}
	ctx_                             context.Context
}

// ResetMultipleForAllPlayers: Resets events with the given IDs for all
// players. This method is only available to user accounts for your
// developer console. Only draft events may be reset. All quests that
// use any of the events will also be reset.
func (r *EventsService) ResetMultipleForAllPlayers(eventsresetmultipleforallrequest *EventsResetMultipleForAllRequest) *EventsResetMultipleForAllPlayersCall {
	c := &EventsResetMultipleForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.eventsresetmultipleforallrequest = eventsresetmultipleforallrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *EventsResetMultipleForAllPlayersCall) Fields(s ...googleapi.Field) *EventsResetMultipleForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *EventsResetMultipleForAllPlayersCall) Context(ctx context.Context) *EventsResetMultipleForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *EventsResetMultipleForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.eventsresetmultipleforallrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "events/resetMultipleForAllPlayers")
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

// Do executes the "gamesManagement.events.resetMultipleForAllPlayers" call.
func (c *EventsResetMultipleForAllPlayersCall) Do() error {
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
	//   "description": "Resets events with the given IDs for all players. This method is only available to user accounts for your developer console. Only draft events may be reset. All quests that use any of the events will also be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.events.resetMultipleForAllPlayers",
	//   "path": "events/resetMultipleForAllPlayers",
	//   "request": {
	//     "$ref": "EventsResetMultipleForAllRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.players.hide":

type PlayersHideCall struct {
	s             *Service
	applicationId string
	playerId      string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Hide: Hide the given player's leaderboard scores from the given
// application. This method is only available to user accounts for your
// developer console.
func (r *PlayersService) Hide(applicationId string, playerId string) *PlayersHideCall {
	c := &PlayersHideCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	c.playerId = playerId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlayersHideCall) Fields(s ...googleapi.Field) *PlayersHideCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlayersHideCall) Context(ctx context.Context) *PlayersHideCall {
	c.ctx_ = ctx
	return c
}

func (c *PlayersHideCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/players/hidden/{playerId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
		"playerId":      c.playerId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.players.hide" call.
func (c *PlayersHideCall) Do() error {
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
	//   "description": "Hide the given player's leaderboard scores from the given application. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.players.hide",
	//   "parameterOrder": [
	//     "applicationId",
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/players/hidden/{playerId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.players.unhide":

type PlayersUnhideCall struct {
	s             *Service
	applicationId string
	playerId      string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Unhide: Unhide the given player's leaderboard scores from the given
// application. This method is only available to user accounts for your
// developer console.
func (r *PlayersService) Unhide(applicationId string, playerId string) *PlayersUnhideCall {
	c := &PlayersUnhideCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	c.playerId = playerId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PlayersUnhideCall) Fields(s ...googleapi.Field) *PlayersUnhideCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PlayersUnhideCall) Context(ctx context.Context) *PlayersUnhideCall {
	c.ctx_ = ctx
	return c
}

func (c *PlayersUnhideCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/players/hidden/{playerId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
		"playerId":      c.playerId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.players.unhide" call.
func (c *PlayersUnhideCall) Do() error {
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
	//   "description": "Unhide the given player's leaderboard scores from the given application. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "DELETE",
	//   "id": "gamesManagement.players.unhide",
	//   "parameterOrder": [
	//     "applicationId",
	//     "playerId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "playerId": {
	//       "description": "A player ID. A value of me may be used in place of the authenticated player's ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/players/hidden/{playerId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.quests.reset":

type QuestsResetCall struct {
	s       *Service
	questId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Reset: Resets all player progress on the quest with the given ID for
// the currently authenticated player. This method is only accessible to
// whitelisted tester accounts for your application.
func (r *QuestsService) Reset(questId string) *QuestsResetCall {
	c := &QuestsResetCall{s: r.s, opt_: make(map[string]interface{})}
	c.questId = questId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsResetCall) Fields(s ...googleapi.Field) *QuestsResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsResetCall) Context(ctx context.Context) *QuestsResetCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/{questId}/reset")
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

// Do executes the "gamesManagement.quests.reset" call.
func (c *QuestsResetCall) Do() error {
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
	//   "description": "Resets all player progress on the quest with the given ID for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.quests.reset",
	//   "parameterOrder": [
	//     "questId"
	//   ],
	//   "parameters": {
	//     "questId": {
	//       "description": "The ID of the quest.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "quests/{questId}/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.quests.resetAll":

type QuestsResetAllCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAll: Resets all player progress on all quests for the currently
// authenticated player. This method is only accessible to whitelisted
// tester accounts for your application.
func (r *QuestsService) ResetAll() *QuestsResetAllCall {
	c := &QuestsResetAllCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsResetAllCall) Fields(s ...googleapi.Field) *QuestsResetAllCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsResetAllCall) Context(ctx context.Context) *QuestsResetAllCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsResetAllCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.quests.resetAll" call.
func (c *QuestsResetAllCall) Do() error {
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
	//   "description": "Resets all player progress on all quests for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.quests.resetAll",
	//   "path": "quests/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.quests.resetAllForAllPlayers":

type QuestsResetAllForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAllForAllPlayers: Resets all draft quests for all players. This
// method is only available to user accounts for your developer console.
func (r *QuestsService) ResetAllForAllPlayers() *QuestsResetAllForAllPlayersCall {
	c := &QuestsResetAllForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsResetAllForAllPlayersCall) Fields(s ...googleapi.Field) *QuestsResetAllForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsResetAllForAllPlayersCall) Context(ctx context.Context) *QuestsResetAllForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsResetAllForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/resetAllForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.quests.resetAllForAllPlayers" call.
func (c *QuestsResetAllForAllPlayersCall) Do() error {
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
	//   "description": "Resets all draft quests for all players. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.quests.resetAllForAllPlayers",
	//   "path": "quests/resetAllForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.quests.resetForAllPlayers":

type QuestsResetForAllPlayersCall struct {
	s       *Service
	questId string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// ResetForAllPlayers: Resets all player progress on the quest with the
// given ID for all players. This method is only available to user
// accounts for your developer console. Only draft quests can be reset.
func (r *QuestsService) ResetForAllPlayers(questId string) *QuestsResetForAllPlayersCall {
	c := &QuestsResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.questId = questId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsResetForAllPlayersCall) Fields(s ...googleapi.Field) *QuestsResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsResetForAllPlayersCall) Context(ctx context.Context) *QuestsResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/{questId}/resetForAllPlayers")
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

// Do executes the "gamesManagement.quests.resetForAllPlayers" call.
func (c *QuestsResetForAllPlayersCall) Do() error {
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
	//   "description": "Resets all player progress on the quest with the given ID for all players. This method is only available to user accounts for your developer console. Only draft quests can be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.quests.resetForAllPlayers",
	//   "parameterOrder": [
	//     "questId"
	//   ],
	//   "parameters": {
	//     "questId": {
	//       "description": "The ID of the quest.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "quests/{questId}/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.quests.resetMultipleForAllPlayers":

type QuestsResetMultipleForAllPlayersCall struct {
	s                                *Service
	questsresetmultipleforallrequest *QuestsResetMultipleForAllRequest
	opt_                             map[string]interface{}
	ctx_                             context.Context
}

// ResetMultipleForAllPlayers: Resets quests with the given IDs for all
// players. This method is only available to user accounts for your
// developer console. Only draft quests may be reset.
func (r *QuestsService) ResetMultipleForAllPlayers(questsresetmultipleforallrequest *QuestsResetMultipleForAllRequest) *QuestsResetMultipleForAllPlayersCall {
	c := &QuestsResetMultipleForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.questsresetmultipleforallrequest = questsresetmultipleforallrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *QuestsResetMultipleForAllPlayersCall) Fields(s ...googleapi.Field) *QuestsResetMultipleForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *QuestsResetMultipleForAllPlayersCall) Context(ctx context.Context) *QuestsResetMultipleForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *QuestsResetMultipleForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.questsresetmultipleforallrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "quests/resetMultipleForAllPlayers")
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

// Do executes the "gamesManagement.quests.resetMultipleForAllPlayers" call.
func (c *QuestsResetMultipleForAllPlayersCall) Do() error {
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
	//   "description": "Resets quests with the given IDs for all players. This method is only available to user accounts for your developer console. Only draft quests may be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.quests.resetMultipleForAllPlayers",
	//   "path": "quests/resetMultipleForAllPlayers",
	//   "request": {
	//     "$ref": "QuestsResetMultipleForAllRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.rooms.reset":

type RoomsResetCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Reset: Reset all rooms for the currently authenticated player for
// your application. This method is only accessible to whitelisted
// tester accounts for your application.
func (r *RoomsService) Reset() *RoomsResetCall {
	c := &RoomsResetCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsResetCall) Fields(s ...googleapi.Field) *RoomsResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsResetCall) Context(ctx context.Context) *RoomsResetCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.rooms.reset" call.
func (c *RoomsResetCall) Do() error {
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
	//   "description": "Reset all rooms for the currently authenticated player for your application. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.rooms.reset",
	//   "path": "rooms/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.rooms.resetForAllPlayers":

type RoomsResetForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetForAllPlayers: Deletes rooms where the only room participants
// are from whitelisted tester accounts for your application. This
// method is only available to user accounts for your developer console.
func (r *RoomsService) ResetForAllPlayers() *RoomsResetForAllPlayersCall {
	c := &RoomsResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RoomsResetForAllPlayersCall) Fields(s ...googleapi.Field) *RoomsResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RoomsResetForAllPlayersCall) Context(ctx context.Context) *RoomsResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *RoomsResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "rooms/resetForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.rooms.resetForAllPlayers" call.
func (c *RoomsResetForAllPlayersCall) Do() error {
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
	//   "description": "Deletes rooms where the only room participants are from whitelisted tester accounts for your application. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.rooms.resetForAllPlayers",
	//   "path": "rooms/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.scores.reset":

type ScoresResetCall struct {
	s             *Service
	leaderboardId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Reset: Resets scores for the leaderboard with the given ID for the
// currently authenticated player. This method is only accessible to
// whitelisted tester accounts for your application.
func (r *ScoresService) Reset(leaderboardId string) *ScoresResetCall {
	c := &ScoresResetCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresResetCall) Fields(s ...googleapi.Field) *ScoresResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresResetCall) Context(ctx context.Context) *ScoresResetCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}/scores/reset")
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

// Do executes the "gamesManagement.scores.reset" call.
// Exactly one of *PlayerScoreResetResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *PlayerScoreResetResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresResetCall) Do() (*PlayerScoreResetResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &PlayerScoreResetResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Resets scores for the leaderboard with the given ID for the currently authenticated player. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.scores.reset",
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
	//   "path": "leaderboards/{leaderboardId}/scores/reset",
	//   "response": {
	//     "$ref": "PlayerScoreResetResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.scores.resetAll":

type ScoresResetAllCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAll: Resets all scores for all leaderboards for the currently
// authenticated players. This method is only accessible to whitelisted
// tester accounts for your application.
func (r *ScoresService) ResetAll() *ScoresResetAllCall {
	c := &ScoresResetAllCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresResetAllCall) Fields(s ...googleapi.Field) *ScoresResetAllCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresResetAllCall) Context(ctx context.Context) *ScoresResetAllCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresResetAllCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "scores/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.scores.resetAll" call.
// Exactly one of *PlayerScoreResetAllResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *PlayerScoreResetAllResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ScoresResetAllCall) Do() (*PlayerScoreResetAllResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &PlayerScoreResetAllResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Resets all scores for all leaderboards for the currently authenticated players. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.scores.resetAll",
	//   "path": "scores/reset",
	//   "response": {
	//     "$ref": "PlayerScoreResetAllResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.scores.resetAllForAllPlayers":

type ScoresResetAllForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetAllForAllPlayers: Resets scores for all draft leaderboards for
// all players. This method is only available to user accounts for your
// developer console.
func (r *ScoresService) ResetAllForAllPlayers() *ScoresResetAllForAllPlayersCall {
	c := &ScoresResetAllForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresResetAllForAllPlayersCall) Fields(s ...googleapi.Field) *ScoresResetAllForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresResetAllForAllPlayersCall) Context(ctx context.Context) *ScoresResetAllForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresResetAllForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "scores/resetAllForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.scores.resetAllForAllPlayers" call.
func (c *ScoresResetAllForAllPlayersCall) Do() error {
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
	//   "description": "Resets scores for all draft leaderboards for all players. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.scores.resetAllForAllPlayers",
	//   "path": "scores/resetAllForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.scores.resetForAllPlayers":

type ScoresResetForAllPlayersCall struct {
	s             *Service
	leaderboardId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// ResetForAllPlayers: Resets scores for the leaderboard with the given
// ID for all players. This method is only available to user accounts
// for your developer console. Only draft leaderboards can be reset.
func (r *ScoresService) ResetForAllPlayers(leaderboardId string) *ScoresResetForAllPlayersCall {
	c := &ScoresResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresResetForAllPlayersCall) Fields(s ...googleapi.Field) *ScoresResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresResetForAllPlayersCall) Context(ctx context.Context) *ScoresResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}/scores/resetForAllPlayers")
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

// Do executes the "gamesManagement.scores.resetForAllPlayers" call.
func (c *ScoresResetForAllPlayersCall) Do() error {
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
	//   "description": "Resets scores for the leaderboard with the given ID for all players. This method is only available to user accounts for your developer console. Only draft leaderboards can be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.scores.resetForAllPlayers",
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
	//   "path": "leaderboards/{leaderboardId}/scores/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.scores.resetMultipleForAllPlayers":

type ScoresResetMultipleForAllPlayersCall struct {
	s                                *Service
	scoresresetmultipleforallrequest *ScoresResetMultipleForAllRequest
	opt_                             map[string]interface{}
	ctx_                             context.Context
}

// ResetMultipleForAllPlayers: Resets scores for the leaderboards with
// the given IDs for all players. This method is only available to user
// accounts for your developer console. Only draft leaderboards may be
// reset.
func (r *ScoresService) ResetMultipleForAllPlayers(scoresresetmultipleforallrequest *ScoresResetMultipleForAllRequest) *ScoresResetMultipleForAllPlayersCall {
	c := &ScoresResetMultipleForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	c.scoresresetmultipleforallrequest = scoresresetmultipleforallrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ScoresResetMultipleForAllPlayersCall) Fields(s ...googleapi.Field) *ScoresResetMultipleForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ScoresResetMultipleForAllPlayersCall) Context(ctx context.Context) *ScoresResetMultipleForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *ScoresResetMultipleForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.scoresresetmultipleforallrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "scores/resetMultipleForAllPlayers")
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

// Do executes the "gamesManagement.scores.resetMultipleForAllPlayers" call.
func (c *ScoresResetMultipleForAllPlayersCall) Do() error {
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
	//   "description": "Resets scores for the leaderboards with the given IDs for all players. This method is only available to user accounts for your developer console. Only draft leaderboards may be reset.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.scores.resetMultipleForAllPlayers",
	//   "path": "scores/resetMultipleForAllPlayers",
	//   "request": {
	//     "$ref": "ScoresResetMultipleForAllRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.turnBasedMatches.reset":

type TurnBasedMatchesResetCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Reset: Reset all turn-based match data for a user. This method is
// only accessible to whitelisted tester accounts for your application.
func (r *TurnBasedMatchesService) Reset() *TurnBasedMatchesResetCall {
	c := &TurnBasedMatchesResetCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesResetCall) Fields(s ...googleapi.Field) *TurnBasedMatchesResetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesResetCall) Context(ctx context.Context) *TurnBasedMatchesResetCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesResetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/reset")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.turnBasedMatches.reset" call.
func (c *TurnBasedMatchesResetCall) Do() error {
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
	//   "description": "Reset all turn-based match data for a user. This method is only accessible to whitelisted tester accounts for your application.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.turnBasedMatches.reset",
	//   "path": "turnbasedmatches/reset",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "gamesManagement.turnBasedMatches.resetForAllPlayers":

type TurnBasedMatchesResetForAllPlayersCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// ResetForAllPlayers: Deletes turn-based matches where the only match
// participants are from whitelisted tester accounts for your
// application. This method is only available to user accounts for your
// developer console.
func (r *TurnBasedMatchesService) ResetForAllPlayers() *TurnBasedMatchesResetForAllPlayersCall {
	c := &TurnBasedMatchesResetForAllPlayersCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *TurnBasedMatchesResetForAllPlayersCall) Fields(s ...googleapi.Field) *TurnBasedMatchesResetForAllPlayersCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *TurnBasedMatchesResetForAllPlayersCall) Context(ctx context.Context) *TurnBasedMatchesResetForAllPlayersCall {
	c.ctx_ = ctx
	return c
}

func (c *TurnBasedMatchesResetForAllPlayersCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "turnbasedmatches/resetForAllPlayers")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesManagement.turnBasedMatches.resetForAllPlayers" call.
func (c *TurnBasedMatchesResetForAllPlayersCall) Do() error {
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
	//   "description": "Deletes turn-based matches where the only match participants are from whitelisted tester accounts for your application. This method is only available to user accounts for your developer console.",
	//   "httpMethod": "POST",
	//   "id": "gamesManagement.turnBasedMatches.resetForAllPlayers",
	//   "path": "turnbasedmatches/resetForAllPlayers",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/games",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}
