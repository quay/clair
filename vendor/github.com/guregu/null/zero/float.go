package zero

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
)

// Float is a nullable float64. Zero input will be considered null.
// JSON marshals to zero if null.
// Considered null to SQL if zero.
type Float struct {
	sql.NullFloat64
}

// NewFloat creates a new Float
func NewFloat(f float64, valid bool) Float {
	return Float{
		NullFloat64: sql.NullFloat64{
			Float64: f,
			Valid:   valid,
		},
	}
}

// FloatFrom creates a new Float that will be null if zero.
func FloatFrom(f float64) Float {
	return NewFloat(f, f != 0)
}

// FloatFromPtr creates a new Float that be null if f is nil.
func FloatFromPtr(f *float64) Float {
	if f == nil {
		return NewFloat(0, false)
	}
	return NewFloat(*f, true)
}

// UnmarshalJSON implements json.Unmarshaler.
// It supports number and null input.
// 0 will be considered a null Float.
// It also supports unmarshalling a sql.NullFloat64.
func (f *Float) UnmarshalJSON(data []byte) error {
	var err error
	var v interface{}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		f.Float64 = x
	case map[string]interface{}:
		err = json.Unmarshal(data, &f.NullFloat64)
	case nil:
		f.Valid = false
		return nil
	default:
		err = fmt.Errorf("json: cannot unmarshal %v into Go value of type zero.Float", reflect.TypeOf(v).Name())
	}
	f.Valid = (err == nil) && (f.Float64 != 0)
	return err
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It will unmarshal to a null Float if the input is a blank, zero, or not a float.
// It will return an error if the input is not a float, blank, or "null".
func (f *Float) UnmarshalText(text []byte) error {
	str := string(text)
	if str == "" || str == "null" {
		f.Valid = false
		return nil
	}
	var err error
	f.Float64, err = strconv.ParseFloat(string(text), 64)
	f.Valid = (err == nil) && (f.Float64 != 0)
	return err
}

// MarshalJSON implements json.Marshaler.
// It will encode null if this Float is null.
func (f Float) MarshalJSON() ([]byte, error) {
	n := f.Float64
	if !f.Valid {
		n = 0
	}
	return []byte(strconv.FormatFloat(n, 'f', -1, 64)), nil
}

// MarshalText implements encoding.TextMarshaler.
// It will encode a zero if this Float is null.
func (f Float) MarshalText() ([]byte, error) {
	n := f.Float64
	if !f.Valid {
		n = 0
	}
	return []byte(strconv.FormatFloat(n, 'f', -1, 64)), nil
}

// SetValid changes this Float's value and also sets it to be non-null.
func (f *Float) SetValid(v float64) {
	f.Float64 = v
	f.Valid = true
}

// Ptr returns a poFloater to this Float's value, or a nil poFloater if this Float is null.
func (f Float) Ptr() *float64 {
	if !f.Valid {
		return nil
	}
	return &f.Float64
}

// IsZero returns true for null or zero Floats, for future omitempty support (Go 1.4?)
func (f Float) IsZero() bool {
	return !f.Valid || f.Float64 == 0
}
