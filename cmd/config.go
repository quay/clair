package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/quay/clair/config"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads the named config file or reports an error.
//
// JSON and YAML formatted files are supported, as determined by the file extension ("json" or "yaml" -- "yml" is not supported).
// If a directory suffixed with ".d" exists (e.g. a file "config.json" and a directory "config.json.d"),
// then all files with the same extension or the same extension suffixed with "-patch" will be loaded in lexical order and merged with the main configuration or applied as an RFC6902 patch, respectively.
//
// For example, given the paths:
//
//	config.yaml
//	config.yaml.d/
//	config.yaml.d/secrets.yaml
//	config.yaml.d/override.yaml-patch
//	config.yaml.d/unloved.json-patch
//
// "Config.yaml" will be the base config,
// "override.yaml-patch" will be applied as a patch to the base config,
// "secrets.yaml" will be merged into the base config,
// and "unloved.json-patch" will be ignored.
//
// The "strict" argument controls whether the function returns on the first
// error, or runs the full routine and returns all accumulated errors at the
// end.
func LoadConfig(cfg *config.Config, name string, strict bool) error {
	// This function would probably benefit from some logging, but the logging
	// configuration is specified _inside_ the configuration, so it's hard to
	// say what should be done here.
	name = filepath.Clean(name)
	ext := filepath.Ext(name)
	switch ext {
	case ".yaml": // OK
	case ".json": // OK
	default:
		return fmt.Errorf("unknown config kind %q", ext)
	}
	var errs []error

	b, err := loadAsJSON(name)
	if err != nil {
		if strict {
			return err
		}
		errs = append(errs, err)
	}
	dropinDir := name + ".d"
	err = filepath.WalkDir(dropinDir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case path == dropinDir:
			return nil
		case !errors.Is(err, nil):
			return fmt.Errorf("error walking filesystem: %w", err)
		case d.IsDir():
			return fs.SkipDir
		}
		// After this, make sure everything assigns errors to "err" so that the
		// non-strict behavior works.

		var doc []byte
		switch dext := filepath.Ext(path); {
		case dext == ext:
			doc, err = loadAsJSON(path)
			if err != nil {
				break
			}
			b, err = jsonpatch.MergePatch(b, doc)
			if err != nil {
				err = fmt.Errorf("error merging drop-in %q: %w", path, err)
				break
			}
		case dext == ext+"-patch":
			doc, err = loadAsJSON(path)
			if err != nil {
				break
			}
			var p jsonpatch.Patch
			p, err = jsonpatch.DecodePatch(doc)
			if err != nil {
				err = fmt.Errorf("bad patch %q: %w", path, err)
				break
			}
			b, err = p.Apply(b)
			if err != nil {
				err = fmt.Errorf("error applying patch %q: %w", path, err)
				break
			}
		}
		if err != nil {
			if strict {
				return err
			}
			errs = append(errs, err)
		}
		return nil
	})
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist): // OK
	case strict:
		return err
	default:
		errs = append(errs, err)
	}

	if len(b) == 0 {
		err := fmt.Errorf("error load config %q: empty document after merges", name)
		if strict {
			return err
		}
		errs = append(errs, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		// Hide that this error is coming from the `json` package, as it might
		// confuse people.
		err := fmt.Errorf("error decoding config %q: %s", name, strings.TrimPrefix(err.Error(), `json: `))
		if strict {
			return err
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func loadAsJSON(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", path, err)
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".json", ".json-patch":
		if len(b) < 2 {
			return nil, fmt.Errorf("malformed file %q: not a JSON document", path)
		}
	case ".yaml", ".yaml-patch":
		var y interface{}
		if err := yaml.Unmarshal(b, &y); err != nil {
			msg := strings.TrimPrefix(err.Error(), `yaml: `)
			return nil, fmt.Errorf("malformed file %q: %v", path, msg)
		}
		// For arbitrary yaml documents we'd have to do a step to ensure there's
		// no disallowed constructs (binary keys, binary data tags) but we know
		// this should only ever be some snippet of our config.Config type.
		b, err = json.Marshal(y)
		if err != nil { // Not sure how this would happen. 🤔
			msg := strings.TrimPrefix(err.Error(), `json: `)
			return nil, fmt.Errorf("malformed file %q: %s", path, msg)
		}
	default:
		panic("programmer error: called on bad path")
	}
	switch ext {
	case ".json":
		if b[0] != '{' {
			return nil, fmt.Errorf("malformed file %q: not a JSON object", path)
		}
	case ".json-patch", ".yaml-patch":
		if b[0] != '[' {
			return nil, fmt.Errorf("malformed file %q: not a patch document", path)
		}
	case ".yaml":
		if b[0] != '{' {
			// If this was an empty file (for some reason), note it and return an
			// empty JSON object. This can't happen with JSON -- we checked if it
			// meets the minimum size above.
			b = []byte("{}")
		}
	}
	return b, nil
}
