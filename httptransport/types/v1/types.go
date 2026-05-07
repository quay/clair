// Package types provides JSON Schemas for the HTTP API.
package types

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/url"
	"path"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
)

//go:generate sh -euc "for f in *.json; do <$DOLLAR{f} >$DOLLAR{f}_ jq -e .; mv $DOLLAR{f}_ $DOLLAR{f}; done"

// Schema holds the JSON Schema for the v1 types.
//
//go:embed *.schema.json
var Schema embed.FS

// SchemaByURL returns a map with all the v1 types in their "resolved" form.
//
// The returned map is shared and must not be mutated.
var SchemaByURL = sync.OnceValue(loadFromEmbed)

// LoadFromEmbed does what it says on the tin.
func loadFromEmbed() map[string]*jsonschema.Resolved {
	// Load is a helper to load Schema though a cache.
	schemaMap := make(map[string]*jsonschema.Schema)
	load := func(name string) (*jsonschema.Schema, error) {
		if s, ok := schemaMap[name]; ok {
			return s, nil
		}

		b, err := fs.ReadFile(Schema, name)
		if err != nil {
			return nil, err
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}

		schemaMap[name] = &s
		return &s, nil
	}

	// Read the list of Schema from the Embed. This should never fail.
	ents, err := fs.ReadDir(Schema, ".")
	if err != nil {
		panic("programmer error: " + err.Error())
	}

	// ResolvedMap will hold the return values.
	resolvedMap := make(map[string]*jsonschema.Resolved)
	// Do the resolution by forwarding to the cached load function.
	opts := &jsonschema.ResolveOptions{
		Loader: func(u *url.URL) (*jsonschema.Schema, error) {
			return load(path.Base(u.Path))
		},
	}
	// For every Schema in the Embed, load and resolve it.
	for _, ent := range ents {
		s, err := load(ent.Name())
		if err != nil {
			panic("programmer error: " + err.Error())
		}
		u, err := url.Parse(s.ID)
		if err != nil {
			panic("programmer error: " + err.Error())
		}
		r, err := s.Resolve(opts)
		if err != nil {
			panic("programmer error: " + err.Error())
		}

		resolvedMap[u.String()] = r
	}
	return resolvedMap
}
