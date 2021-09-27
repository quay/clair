package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Lint runs lints on the provided Config.
//
// An error is reported only if an error occurred while running the lints. An
// invalid Config may still report a nil error along with a slice of Warnings.
func Lint(c *Config) ([]Warning, error) {
	// The linter does a teeny bit of reflection with an internal interface to
	// check different values.
	ws := []Warning{}
	v := reflect.ValueOf(c)
	path := "$"
	var walk func(string, reflect.Value) error
	walk = func(path string, v reflect.Value) error {
		t := v.Type()
		var vi interface{}
		// Figure out if we should take the address to do the interface
		// assertion, or if the value is already a pointer.
		switch {
		case t.Kind() != reflect.Ptr && v.CanAddr():
			vi = v.Addr().Interface()
		case v.CanInterface() && v.IsValid() && !v.IsZero():
			vi = v.Interface()
		}

		if l, ok := vi.(linter); ok {
			w, err := l.lint()
			if err != nil {
				return err
			}
			for i := range w {
				// Adjust the path here, so that the lint method doesn't need to
				// know where it is.
				w[i].path = path + w[i].path
			}
			ws = append(ws, w...)
		}

		// Dereference the pointer, if this is a pointer.
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
			v = v.Elem()
		}
		if !v.IsValid() {
			return nil
		}
		switch t.Kind() {
		case reflect.Struct:
			for i, lim := 0, t.NumField(); i < lim; i++ {
				f := t.Field(i)
				n := f.Name
				if t := f.Tag.Get("json"); t != "" && t != "-" {
					// Handle the comma options.
					if i := strings.IndexByte(t, ','); i != -1 {
						t = t[:i]
					}
					n = t
				}
				p := fmt.Sprintf(`%s.%s`, path, n)
				if err := walk(p, v.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Map:
			i := v.MapRange()
			for i.Next() {
				p := fmt.Sprintf(`%s.[%s]`, path, i.Key().String())
				if err := walk(p, i.Value()); err != nil {
					return err
				}

			}
		case reflect.Slice:
			for i, lim := 0, v.Len(); i < lim; i++ {
				p := fmt.Sprintf(`%s.[%d]`, path, i)
				if err := walk(p, v.Index(i)); err != nil {
					return err
				}
			}
		default:
			// everything else, just pass
		}
		return nil
	}
	return ws, walk(path, v)
}

// Types in this package can implement this interface to report common issues or
// deprecation warnings.
type linter interface {
	lint() ([]Warning, error)
}

// Warning is a linter warning.
//
// Users can treat them like errors and use the sentinel values exported by this
// package.
type Warning struct {
	inner error
	path  string // json-schema style path
	msg   string
}

// Should have inner xor msg

func (w *Warning) Error() string {
	var b strings.Builder
	if w.inner != nil {
		b.WriteString(w.inner.Error())
	} else {
		b.WriteString(w.msg)
	}
	b.WriteString(" (at ")
	b.WriteString(w.path)
	b.WriteRune(')')
	return b.String()
}

func (w *Warning) Unwrap() error { return w.inner }

// These are some common kinds of Warnings.
var (
	ErrDeprecated = errors.New("setting will be removed in a future release")
)
