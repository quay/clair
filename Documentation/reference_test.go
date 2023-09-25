package Documentation

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/clair/config"
)

func TestConfigReference(t *testing.T) {
	f, err := os.Open("reference/config.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	header := regexp.MustCompile("^#+ `\\$[^`]+`")
	var got []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if header.Match(s.Bytes()) {
			got = append(got, strings.Trim(s.Text(), " #`"))
		}
	}
	if err := s.Err(); err != nil {
		t.Error(err)
	}
	var want []string
	if err := walk(&want, "$", reflect.TypeOf(config.Config{})); err != nil {
		t.Error(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

type walkFunc func(interface{}) ([]string, error)

func walk(ws *[]string, path string, t reflect.Type) error {
	// Dereference the pointer, if this is a pointer.
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() == reflect.Struct {
		for i, lim := 0, t.NumField(); i < lim; i++ {
			f := t.Field(i)
			if f.Anonymous {
				if err := walk(ws, path, t.Field(i).Type); err != nil {
					return err
				}
				continue
			}
			var n string
			switch t := f.Tag.Get("json"); t {
			case "-", "":
				continue
			default:
				if i := strings.IndexByte(t, ','); i != -1 {
					t = t[:i]
				}
				n = t
			}
			p := fmt.Sprintf(`%s.%s`, path, n)
			*ws = append(*ws, p)
			if err := walk(ws, p, t.Field(i).Type); err != nil {
				return err
			}
		}
	}
	return nil
}
