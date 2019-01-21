// Copyright 2019 clair authors
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

package stomp

import (
	"testing"

	"github.com/go-stomp/stomp/frame"
	"github.com/stretchr/testify/assert"
)

type MockConnetion struct {
}

func (c *MockConnetion) Disconnect() error {
	return nil
}

func (c *MockConnetion) Send(destination, contentType string, body []byte, opts ...func(*frame.Frame) error) error {
	return nil
}

func TestSend(t *testing.T) {
	mockConnection := &MockConnetion{}

	sender := Sender{StompConn: mockConnection}
	err := sender.Send("foo")
	assert.Equal(t, err, nil)
	assert.Equal(t, sender.StompConn, nil)

}
