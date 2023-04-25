package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/notifier"
)

// TestPagination confirms paginating notifications works correctly.
func TestPagination(t *testing.T) {
	integration.NeedDB(t)

	table := []struct {
		// name of test
		name string
		// total number of notifications to request
		total int
		// number of notifications per page to test
		pageSize int
	}{
		{
			name:     "TotalZero",
			total:    0,
			pageSize: 1,
		},
		{
			name:     "PageOne",
			total:    5,
			pageSize: 1,
		},
		{
			name:     "Ones",
			total:    1,
			pageSize: 1,
		},
		{
			name:     "OddsGT",
			total:    3,
			pageSize: 7,
		},
		{
			name:     "OddsLT",
			total:    7,
			pageSize: 3,
		},
		{
			name:     "LT",
			total:    1000,
			pageSize: 5,
		},
		{
			name:     "GT",
			total:    5,
			pageSize: 1000,
		},
		{
			name:     "Large",
			total:    5000,
			pageSize: 1000,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = zlog.Test(ctx, t)
			store := TestingStore(ctx, t)

			noteID := uuid.New()
			updateID := uuid.New()
			manifestHash := claircore.MustParseDigest("sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a")

			notes := make([]notifier.Notification, 0, tt.total)
			for i := 0; i < tt.total; i++ {
				notes = append(notes, notifier.Notification{
					Manifest: manifestHash,
					Reason:   "added",
				})
			}
			t.Logf("inserting %v notes", len(notes))
			err := store.PutNotifications(ctx, notifier.PutOpts{
				Updater:        "test-updater",
				NotificationID: noteID,
				Notifications:  notes,
				UpdateID:       updateID,
			})
			if err != nil {
				t.Fatalf("failed to insert notifications: %v", err)
			}

			inPage := notifier.Page{
				Size: tt.pageSize,
			}

			total := []notifier.Notification{}
			returned, outPage, err := store.Notifications(ctx, noteID, &inPage)
			if err != nil {
				t.Fatalf("failed to retrieve initial page: %v", err)
			}
			total = append(total, returned...)

			for outPage.Next != nil {
				if outPage.Size != tt.pageSize {
					t.Fatalf("got: %v, want: %v", outPage.Size, tt.pageSize)
				}
				if len(returned) > tt.pageSize {
					t.Fatalf("got: %v, want: %v", len(returned), tt.pageSize)
				}
				returned, outPage, err = store.Notifications(ctx, noteID, &outPage)
				total = append(total, returned...)
				if err != nil {
					t.Error(err)
				}
			}

			if len(total) != tt.total {
				t.Fatalf("got: %v, want: %v", len(total), tt.total)
			}
		})
	}
}
