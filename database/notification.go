// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package database

import (
	"encoding/json"
	"strconv"

	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/pborman/uuid"
)

const (
	// maxNotifications is the number of notifications that InsertNotifications
	// will accept at the same time. Above this number, notifications are ignored.
	maxNotifications = 100

	fieldNotificationIsValue = "notification"
	fieldNotificationType    = "type"
	fieldNotificationData    = "data"
	fieldNotificationIsSent  = "isSent"
)

// A Notification defines an interface to a message that can be sent by a
// notifier.Notifier.
// A NotificationWrapper has to be used to convert it into a NotificationWrap,
// which can be stored in the database.
type Notification interface {
	// GetName returns the explicit (humanly meaningful) name of a notification.
	GetName() string
	// GetType returns the type of a notification, which is used by a
	// NotificationWrapper to determine the concrete type of a Notification.
	GetType() string
	// GetContent returns the content of the notification.
	GetContent() (interface{}, error)
}

// NotificationWrapper is an interface defined how to convert a Notification to
// a NotificationWrap object and vice-versa.
type NotificationWrapper interface {
	// Wrap packs a Notification instance into a new NotificationWrap.
	Wrap(n Notification) (*NotificationWrap, error)
	// Unwrap unpacks an instance of NotificationWrap into a new Notification.
	Unwrap(nw *NotificationWrap) (Notification, error)
}

// A NotificationWrap wraps a Notification into something that can be stored in
// the database. A NotificationWrapper has to be used to convert it into a
// Notification.
type NotificationWrap struct {
	Type string
	Data string
}

// DefaultWrapper is an implementation of NotificationWrapper that supports
// NewVulnerabilityNotification notifications.
type DefaultWrapper struct{}

func (w *DefaultWrapper) Wrap(n Notification) (*NotificationWrap, error) {
	data, err := json.Marshal(n)
	if err != nil {
		log.Warningf("could not marshal notification [ID: %s, Type: %s]: %s", n.GetName(), n.GetType(), err)
		return nil, cerrors.NewBadRequestError("could not marshal notification with DefaultWrapper")
	}

	return &NotificationWrap{Type: n.GetType(), Data: string(data)}, nil
}

func (w *DefaultWrapper) Unwrap(nw *NotificationWrap) (Notification, error) {
	var v Notification

	// Create struct depending on the type
	switch nw.Type {
	case "NewVulnerabilityNotification":
		v = &NewVulnerabilityNotification{}
	case "VulnerabilityPriorityIncreasedNotification":
		v = &VulnerabilityPriorityIncreasedNotification{}
	case "VulnerabilityPackageChangedNotification":
		v = &VulnerabilityPackageChangedNotification{}
	default:
		log.Warningf("could not unwrap notification [Type: %s]: unknown type for DefaultWrapper", nw.Type)
		return nil, cerrors.NewBadRequestError("could not unwrap notification")
	}

	// Unmarshal notification
	err := json.Unmarshal([]byte(nw.Data), v)
	if err != nil {
		log.Warningf("could not unmarshal notification with DefaultWrapper [Type: %s]: %s", nw.Type, err)
		return nil, cerrors.NewBadRequestError("could not unmarshal notification")
	}

	return v, nil
}

// GetDefaultNotificationWrapper returns the default wrapper
func GetDefaultNotificationWrapper() NotificationWrapper {
	return &DefaultWrapper{}
}

// A NewVulnerabilityNotification is a notification that informs about a new
// vulnerability and contains all the layers that introduce that vulnerability
type NewVulnerabilityNotification struct {
	VulnerabilityID string
}

func (n *NewVulnerabilityNotification) GetName() string {
	return n.VulnerabilityID
}

func (n *NewVulnerabilityNotification) GetType() string {
	return "NewVulnerabilityNotification"
}

func (n *NewVulnerabilityNotification) GetContent() (interface{}, error) {
	// This notification is about a new vulnerability
	// Returns the list of layers that introduce this vulnerability

	// Find vulnerability.
	vulnerability, err := FindOneVulnerability(n.VulnerabilityID, []string{FieldVulnerabilityID, FieldVulnerabilityLink, FieldVulnerabilityPriority, FieldVulnerabilityDescription, FieldVulnerabilityFixedIn})
	if err != nil {
		return []byte{}, err
	}
	abstractVulnerability, err := vulnerability.ToAbstractVulnerability()
	if err != nil {
		return []byte{}, err
	}

	layers, err := FindAllLayersIntroducingVulnerability(n.VulnerabilityID, []string{FieldLayerID})

	if err != nil {
		return []byte{}, err
	}

	layersIDs := []string{} // empty slice, not null
	for _, l := range layers {
		layersIDs = append(layersIDs, l.ID)
	}

	return struct {
		Vulnerability        *AbstractVulnerability
		IntroducingLayersIDs []string
	}{
		Vulnerability:        abstractVulnerability,
		IntroducingLayersIDs: layersIDs,
	}, nil
}

// A VulnerabilityPriorityIncreasedNotification is a notification that informs
// about the fact that the priority of a vulnerability increased
// vulnerability and contains all the layers that introduce that vulnerability.
type VulnerabilityPriorityIncreasedNotification struct {
	VulnerabilityID          string
	OldPriority, NewPriority types.Priority
}

func (n *VulnerabilityPriorityIncreasedNotification) GetName() string {
	return n.VulnerabilityID
}

func (n *VulnerabilityPriorityIncreasedNotification) GetType() string {
	return "VulnerabilityPriorityIncreasedNotification"
}

func (n *VulnerabilityPriorityIncreasedNotification) GetContent() (interface{}, error) {
	// Returns the list of layers that introduce this vulnerability
	// And both the old and new priorities

	// Find vulnerability.
	vulnerability, err := FindOneVulnerability(n.VulnerabilityID, []string{FieldVulnerabilityID, FieldVulnerabilityLink, FieldVulnerabilityPriority, FieldVulnerabilityDescription, FieldVulnerabilityFixedIn})
	if err != nil {
		return []byte{}, err
	}
	abstractVulnerability, err := vulnerability.ToAbstractVulnerability()
	if err != nil {
		return []byte{}, err
	}

	layers, err := FindAllLayersIntroducingVulnerability(n.VulnerabilityID, []string{FieldLayerID})

	if err != nil {
		return []byte{}, err
	}

	layersIDs := []string{} // empty slice, not null
	for _, l := range layers {
		layersIDs = append(layersIDs, l.ID)
	}

	return struct {
		Vulnerability            *AbstractVulnerability
		OldPriority, NewPriority types.Priority
		IntroducingLayersIDs     []string
	}{
		Vulnerability:        abstractVulnerability,
		OldPriority:          n.OldPriority,
		NewPriority:          n.NewPriority,
		IntroducingLayersIDs: layersIDs,
	}, nil
}

// A VulnerabilityPackageChangedNotification is a notification that informs that
// an existing vulnerability's fixed package list has been updated and may not
// affect some layers anymore or may affect new layers.
type VulnerabilityPackageChangedNotification struct {
	VulnerabilityID                        string
	AddedFixedInNodes, RemovedFixedInNodes []string
}

func (n *VulnerabilityPackageChangedNotification) GetName() string {
	return n.VulnerabilityID
}

func (n *VulnerabilityPackageChangedNotification) GetType() string {
	return "VulnerabilityPackageChangedNotification"
}

func (n *VulnerabilityPackageChangedNotification) GetContent() (interface{}, error) {
	// Returns the removed and added packages as well as the layers that
	// introduced the vulnerability in the past but don't anymore because of the
	// removed packages and the layers that now introduce the vulnerability
	// because of the added packages

	// Find vulnerability.
	vulnerability, err := FindOneVulnerability(n.VulnerabilityID, []string{FieldVulnerabilityID, FieldVulnerabilityLink, FieldVulnerabilityPriority, FieldVulnerabilityDescription, FieldVulnerabilityFixedIn})
	if err != nil {
		return []byte{}, err
	}
	abstractVulnerability, err := vulnerability.ToAbstractVulnerability()
	if err != nil {
		return []byte{}, err
	}

	// First part of the answer : added/removed packages
	addedPackages, err := FindAllPackagesByNodes(n.AddedFixedInNodes, []string{FieldPackageOS, FieldPackageName, FieldPackageVersion, FieldPackagePreviousVersion})
	if err != nil {
		return []byte{}, err
	}
	removedPackages, err := FindAllPackagesByNodes(n.RemovedFixedInNodes, []string{FieldPackageOS, FieldPackageName, FieldPackageVersion, FieldPackagePreviousVersion})
	if err != nil {
		return []byte{}, err
	}

	// Second part of the answer
	var addedPackagesPreviousVersions []string
	for _, pkg := range addedPackages {
		previousVersions, err := pkg.PreviousVersions([]string{})
		if err != nil {
			return []*Layer{}, err
		}
		for _, version := range previousVersions {
			addedPackagesPreviousVersions = append(addedPackagesPreviousVersions, version.Node)
		}
	}
	var removedPackagesPreviousVersions []string
	for _, pkg := range removedPackages {
		previousVersions, err := pkg.PreviousVersions([]string{})
		if err != nil {
			return []*Layer{}, err
		}
		for _, version := range previousVersions {
			removedPackagesPreviousVersions = append(removedPackagesPreviousVersions, version.Node)
		}
	}

	newIntroducingLayers, err := FindAllLayersByAddedPackageNodes(addedPackagesPreviousVersions, []string{FieldLayerID})
	if err != nil {
		return []byte{}, err
	}
	formerIntroducingLayers, err := FindAllLayersByAddedPackageNodes(removedPackagesPreviousVersions, []string{FieldLayerID})
	if err != nil {
		return []byte{}, err
	}

	newIntroducingLayersIDs := []string{} // empty slice, not null
	for _, l := range newIntroducingLayers {
		newIntroducingLayersIDs = append(newIntroducingLayersIDs, l.ID)
	}
	formerIntroducingLayersIDs := []string{} // empty slice, not null
	for _, l := range formerIntroducingLayers {
		formerIntroducingLayersIDs = append(formerIntroducingLayersIDs, l.ID)
	}

	// Remove layers which appears both in new and former lists (eg. case of updated packages but still vulnerable)
	filteredNewIntroducingLayersIDs := utils.CompareStringLists(newIntroducingLayersIDs, formerIntroducingLayersIDs)
	filteredFormerIntroducingLayersIDs := utils.CompareStringLists(formerIntroducingLayersIDs, newIntroducingLayersIDs)

	return struct {
		Vulnerability                                      *AbstractVulnerability
		AddedAffectedPackages, RemovedAffectedPackages     []*AbstractPackage
		NewIntroducingLayersIDs, FormerIntroducingLayerIDs []string
	}{
		Vulnerability:             abstractVulnerability,
		AddedAffectedPackages:     PackagesToAbstractPackages(addedPackages),
		RemovedAffectedPackages:   PackagesToAbstractPackages(removedPackages),
		NewIntroducingLayersIDs:   filteredNewIntroducingLayersIDs,
		FormerIntroducingLayerIDs: filteredFormerIntroducingLayersIDs,
	}, nil
}

// InsertNotifications stores multiple Notification in the database
// It uses the given NotificationWrapper to convert these notifications to
// something that can be stored in the database.
func InsertNotifications(notifications []Notification, wrapper NotificationWrapper) error {
	if len(notifications) == 0 {
		return nil
	}

	// Do not send notifications if there are too many of them (first update for example)
	if len(notifications) > maxNotifications {
		log.Noticef("Ignoring %d notifications", len(notifications))
		return nil
	}

	// Initialize transaction
	t := cayley.NewTransaction()

	// Iterate over all the vulnerabilities we need to insert
	for _, notification := range notifications {
		// Wrap notification
		wrappedNotification, err := wrapper.Wrap(notification)
		if err != nil {
			return err
		}

		node := fieldNotificationIsValue + ":" + uuid.New()
		t.AddQuad(cayley.Triple(node, fieldIs, fieldNotificationIsValue))
		t.AddQuad(cayley.Triple(node, fieldNotificationType, wrappedNotification.Type))
		t.AddQuad(cayley.Triple(node, fieldNotificationData, wrappedNotification.Data))
		t.AddQuad(cayley.Triple(node, fieldNotificationIsSent, strconv.FormatBool(false)))
	}

	// Apply transaction
	if err := store.ApplyTransaction(t); err != nil {
		log.Errorf("failed transaction (InsertNotifications): %s", err)
		return ErrTransaction
	}

	return nil
}

// FindOneNotificationToSend finds and returns a notification that is not sent
// yet and not locked. Returns nil if there is none.
func FindOneNotificationToSend(wrapper NotificationWrapper) (string, Notification, error) {
	it, _ := cayley.StartPath(store, fieldNotificationIsValue).In(fieldIs).Has(fieldNotificationIsSent, strconv.FormatBool(false)).Except(getLockedNodes()).Save(fieldNotificationType, fieldNotificationType).Save(fieldNotificationData, fieldNotificationData).BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		notification, err := wrapper.Unwrap(&NotificationWrap{Type: store.NameOf(tags[fieldNotificationType]), Data: store.NameOf(tags[fieldNotificationData])})
		if err != nil {
			return "", nil, err
		}

		return store.NameOf(it.Result()), notification, nil
	}
	if it.Err() != nil {
		log.Errorf("failed query in FindOneNotificationToSend: %s", it.Err())
		return "", nil, ErrBackendException
	}

	return "", nil, nil
}

// CountNotificationsToSend returns the number of pending notifications
// Note that it also count the locked notifications.
func CountNotificationsToSend() (int, error) {
	c := 0

	it, _ := cayley.StartPath(store, fieldNotificationIsValue).In(fieldIs).Has(fieldNotificationIsSent, strconv.FormatBool(false)).BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		c = c + 1
	}
	if it.Err() != nil {
		log.Errorf("failed query in CountNotificationsToSend: %s", it.Err())
		return 0, ErrBackendException
	}

	return c, nil
}

// MarkNotificationAsSent marks a notification as sent.
func MarkNotificationAsSent(node string) {
	// Initialize transaction
	t := cayley.NewTransaction()

	t.RemoveQuad(cayley.Triple(node, fieldNotificationIsSent, strconv.FormatBool(false)))
	t.AddQuad(cayley.Triple(node, fieldNotificationIsSent, strconv.FormatBool(true)))

	// Apply transaction
	store.ApplyTransaction(t)
}
