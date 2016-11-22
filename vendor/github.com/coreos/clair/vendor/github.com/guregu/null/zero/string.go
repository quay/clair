// Package zero contains SQL types that consider zero input and null input to be equivalent
// with convenient support for JSON and text marshaling.
// Types in this package will JSON marshal to their zero value, even if null.
// Use the null parent package if you don't want this.
package zero

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
)

// String is a nullable string.
// JSON marshals to a blank string if null.
// Considered null to SQL if zero.
type String struct {
	sql.NullString
}

// NewString creates a new String
func NewString(s string, valid bool) String {
	return String{
		NullString: sql.NullString{
			String: s,
			Valid:  valid,
		},
	}
}

// StringFrom creates a new String that will be null if s is blank.
func StringFrom(s string) String {
	return NewString(s, s != "")
}

// StringFromPtr creates a new String that be null if s is nil or blank.
// It will make s point to the String's value.
func StringFromPtr(s *string) String {
	if s == nil {
		return NewString("", false)
	}
	return NewString(*s, *s != "")
}

// UnmarshalJSON implements json.Unmarshaler.
// It supports string and null input. Blank string input produces a null String.
// It also supports unmarshalling a sql.NullString.
func (s *String) UnmarshalJSON(data []byte) error {
	var err error
	var v interface{}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		s.String = x
	case map[string]interface{}:
		err = json.Unmarshal(data, &s.NullString)
	case nil:
		s.Valid = false
		return nil
	default:
		err = fmt.Errorf("json: cannot unmarshal %v into Go value of type zero.String", reflect.TypeOf(v).Name())
	}
	s.Valid = (err == nil) && (s.String != "")
	return err
}

// MarshalText implements encoding.TextMarshaler.
// It will encode a blank string when this String is null.
func (s String) MarshalText() ([]byte, error) {
	if !s.Valid {
		return []byte{}, nil
	}
	return []byte(s.String), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It will unmarshal to a null String if the input is a blank string.
func (s *String) UnmarshalText(text []byte) error {
	s.String = string(text)
	s.Valid = s.String != ""
	return nil
}

// SetValid changes this String's value and also sets it to be non-null.
func (s *String) SetValid(v string) {
	s.String = v
	s.Valid = true
}

// Ptr returns a pointer to this String's value, or a nil pointer if this String is null.
func (s String) Ptr() *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}

// IsZero returns true for null or empty strings, for future omitempty support. (Go 1.4?)
func (s String) IsZero() bool {
	return !s.Valid || s.String == ""
}
