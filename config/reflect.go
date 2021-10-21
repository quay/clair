package config

import (
	"fmt"
	"reflect"
	"strings"
)

type walkFunc func(interface{}) ([]Warning, error)

func forEach(i interface{}, f walkFunc) ([]Warning, error) {
	var ws []Warning
	v := reflect.ValueOf(i)
	return ws, walk(&ws, "$", v, f)
}

func walk(ws *[]Warning, path string, v reflect.Value, wf walkFunc) error {
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

	if vi != nil {
		w, err := wf(vi)
		if err != nil {
			return err
		}
		for i := range w {
			// Adjust the path here, so that the lint method doesn't need to
			// know where it is.
			w[i].path = path + w[i].path
		}
		*ws = append(*ws, w...)
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
			if err := walk(ws, p, v.Field(i), wf); err != nil {
				return err
			}
		}
	case reflect.Map:
		i := v.MapRange()
		for i.Next() {
			p := fmt.Sprintf(`%s.[%s]`, path, i.Key().String())
			if err := walk(ws, p, i.Value(), wf); err != nil {
				return err
			}

		}
	case reflect.Slice:
		for i, lim := 0, v.Len(); i < lim; i++ {
			p := fmt.Sprintf(`%s.[%d]`, path, i)
			if err := walk(ws, p, v.Index(i), wf); err != nil {
				return err
			}
		}
	default:
		// everything else, just pass
	}
	return nil
}
