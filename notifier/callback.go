package notifier

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
)

// Callback holds the details for clients to call back the Notifier
// and receive notifications.
type Callback struct {
	NotificationID uuid.UUID `json:"notification_id"`
	Callback       url.URL   `json:"callback"`
}

func (cb Callback) MarshalJSON() ([]byte, error) {
	var m = map[string]string{
		"notification_id": cb.NotificationID.String(),
		"callback":        cb.Callback.String(),
	}
	return json.Marshal(m)
}

func (cb *Callback) UnmarshalJSON(b []byte) error {
	var m = make(map[string]string, 2)
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	if _, ok := m["notification_id"]; !ok {
		return fmt.Errorf("json unmarshal failed. webhook requires a \"notification_id\" field")
	}
	if _, ok := m["callback"]; !ok {
		return fmt.Errorf("json unmarshal failed. webhook requires a \"callback\" field")
	}

	uid, err := uuid.Parse(m["notification_id"])
	if err != nil {
		return fmt.Errorf("json unmarshal failed. malformed notification uuid: %v", err)
	}
	cbURL, err := url.Parse(m["callback"])
	if err != nil {
		return fmt.Errorf("json unmarshal failed. malformed callback url: %v", err)
	}

	(*cb).NotificationID = uid
	(*cb).Callback = *cbURL
	return nil
}
