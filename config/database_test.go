package config

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDatabaseUnmarshal(t *testing.T) {
	want := Database{
		Name: "postgresql",
		PostgreSQL: &DatabasePostgreSQL{
			DSN: "host=test",
		},
	}
	input := []string{
		`{"name":"postgresql","postgresql":{"dsn":"host=test"}}`,
	}

	for _, tc := range input {
		t.Logf("testing: %#q", tc)
		var got Database
		if err := json.Unmarshal([]byte(tc), &got); err != nil {
			t.Error(err)
			continue
		}
		ws, err := got.lint()
		if err != nil {
			t.Error(err)
			continue
		}
		for _, w := range ws {
			t.Logf("got lint: %v", &w)
		}
		if !cmp.Equal(&got, &want) {
			t.Error(cmp.Diff(&got, &want))
		}
	}
}
