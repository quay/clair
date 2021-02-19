package notifier

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestCallbackSerializtion(t *testing.T) {
	var want = []byte(`{"callback":"https://example.com","notification_id":"00000000-0000-0000-0000-000000000000"}`)
	cb := Callback{
		NotificationID: uuid.Nil,
	}
	u, err := url.Parse("https://example.com")
	if err != nil {
		t.Error(err)
	}
	cb.Callback = *u
	got, err := json.Marshal(&cb)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}

	var rt Callback
	if err := json.Unmarshal(want, &rt); err != nil {
		t.Error(err)
	}
	got, err = json.Marshal(&rt)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
