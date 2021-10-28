package config

import (
	"reflect"
	"testing"
)

// TestTags checks that exported types and fields used in the root Config struct
// have struct tags.
func TestTags(t *testing.T) {
	t.Logf("checking for: %v", wanttags)
	nt := reflect.TypeOf(Config{})
	t.Run(nt.Name(), func(t *testing.T) { typecheck(t, nt) })
}

var wanttags = []string{`json`, `yaml`}

func typecheck(t *testing.T, typ reflect.Type) {
	for i, lim := 0, typ.NumField(); i < lim; i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			// TODO(hank) Use the IsExported method once 1.16 support is
			// dropped.
			continue
		}
		// track the number of names for this field
		vals := make(map[string]struct{})
		// track which tag has which name
		tagval := make(map[string]string)
		for _, n := range wanttags {
			if v, ok := f.Tag.Lookup(n); !ok {
				t.Errorf("%s.%s: missing %q tag", typ.Name(), f.Name, n)
			} else {
				vals[v] = struct{}{}
				tagval[n] = v
			}
		}
		if len(vals) != 1 {
			t.Errorf("different names for %q: %v", f.Name, tagval)
		}
		// Recurse on structs and pointers-to-structs.
		switch nt := f.Type; nt.Kind() {
		case reflect.Ptr:
			pt := nt.Elem()
			if pt.Kind() != reflect.Struct {
				break
			}
			nt = nt.Elem()
			fallthrough
		case reflect.Struct:
			t.Run(nt.Name(), func(t *testing.T) { typecheck(t, nt) })
		}
	}
}
