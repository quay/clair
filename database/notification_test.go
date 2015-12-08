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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/clair/config"
	"github.com/stretchr/testify/assert"
)

type TestWrapper struct{}

func (w *TestWrapper) Wrap(n Notification) (*NotificationWrap, error) {
	data, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	return &NotificationWrap{Type: n.GetType(), Data: string(data)}, nil
}

func (w *TestWrapper) Unwrap(nw *NotificationWrap) (Notification, error) {
	var v Notification

	switch nw.Type {
	case "ntest1":
		v = &NotificationTest1{}
	case "ntest2":
		v = &NotificationTest2{}
	default:
		return nil, fmt.Errorf("Could not Unwrap NotificationWrapper [Type: %s, Data: %s]: Unknown notification type.", nw.Type, nw.Data)
	}

	err := json.Unmarshal([]byte(nw.Data), v)
	return v, err
}

type NotificationTest1 struct {
	Test1 string
}

func (n NotificationTest1) GetName() string {
	return n.Test1
}

func (n NotificationTest1) GetType() string {
	return "ntest1"
}

func (n NotificationTest1) GetContent() (interface{}, error) {
	return struct{ Test1 string }{Test1: n.Test1}, nil
}

type NotificationTest2 struct {
	Test2 string
}

func (n NotificationTest2) GetName() string {
	return n.Test2
}

func (n NotificationTest2) GetType() string {
	return "ntest2"
}

func (n NotificationTest2) GetContent() (interface{}, error) {
	return struct{ Test2 string }{Test2: n.Test2}, nil
}

func TestNotification(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	wrapper := &TestWrapper{}

	// Insert two notifications of different types
	n1 := &NotificationTest1{Test1: "test1"}
	n2 := &NotificationTest2{Test2: "test2"}
	err := InsertNotifications([]Notification{n1, n2}, &TestWrapper{})
	assert.Nil(t, err)

	// Count notifications to send
	c, err := CountNotificationsToSend()
	assert.Nil(t, err)
	assert.Equal(t, 2, c)

	foundN1 := false
	foundN2 := false

	// Select the first one
	node, n, err := FindOneNotificationToSend(wrapper)
	assert.Nil(t, err)
	if assert.NotNil(t, n) {
		if reflect.DeepEqual(n1, n) {
			foundN1 = true
		} else if reflect.DeepEqual(n2, n) {
			foundN2 = true
		} else {
			assert.Fail(t, "did not find any expected notification")
			return
		}
	}

	// Mark the first one as sent
	MarkNotificationAsSent(node)

	// Count notifications to send
	c, err = CountNotificationsToSend()
	assert.Nil(t, err)
	assert.Equal(t, 1, c)

	// Select again
	node, n, err = FindOneNotificationToSend(wrapper)
	assert.Nil(t, err)
	if foundN1 {
		assert.Equal(t, n2, n)
	} else if foundN2 {
		assert.Equal(t, n1, n)
	}

	// Lock the second one
	Lock(node, time.Minute, "TestNotification")

	// Select again
	_, n, err = FindOneNotificationToSend(wrapper)
	assert.Nil(t, err)
	assert.Equal(t, nil, n)
}
