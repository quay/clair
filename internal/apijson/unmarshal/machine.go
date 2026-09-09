package unmarshal

import (
	"encoding"
	"fmt"
	"reflect"

	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// Machine is the decoding state machine.
type machine[V any] struct {
	dec   *jsontext.Decoder
	out   *V
	err   error
	state stateFn[V]
}

// StateFn is a function pointer to a [machine] state.
//
// Nil is the terminal state.
type stateFn[V any] func(*machine[V]) stateFn[V]

// RunMachine runs a machine to a terminal state, reporting any error that
// occurred.
func runMachine[V any](dec *jsontext.Decoder, out *V, init stateFn[V]) error {
	m := machine[V]{
		dec: dec,
		out: out,
		err: nil,
	}
	state := init
	for state != nil {
		state = state(&m)
	}

	return m.err
}

// Error sets the machine's error and returns the terminal state.
func (m *machine[V]) Error(err error) stateFn[V] {
	m.err = err
	return nil
}

// InvalidObjectKey is a wrapper around [*machine.Error].
func (m *machine[V]) InvalidObjectKey() stateFn[V] {
	return m.Error(fmt.Errorf("invalid object key (at %s)", m.dec.StackPointer()))
}

// Expect reports if the next [jsontext.Token] is of the indicated [jsontext.Kind].
//
// The next token is always consumed and only returned if successfully read and
// of the expected Kind.
func (m *machine[V]) Expect(want jsontext.Kind) (jsontext.Token, error) {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return jsontext.Token{}, err
	}
	if got := tok.Kind(); got != want {
		err := fmt.Errorf("unexpected token (at %s): got %q, want %q: %w", m.dec.StackPointer(), tok, want, m.dec.SkipValue())
		return jsontext.Token{}, err
	}
	return tok, nil
}

// Bool interprets the next [jsontext.Token] as a boolean, stores it in the
// passed address, then returns "next".
func (m *machine[V]) Bool(out *bool, next stateFn[V]) stateFn[V] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}
	switch tok.Kind() {
	case kindTrue, kindFalse:
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q, want %q: %w", m.dec.StackPointer(), tok, "t/f", m.dec.SkipValue())
		return m.Error(err)
	}
	*out = tok.Bool()
	return next
}

// String interprets the next [jsontext.Token] as a string, stores it in the
// passed address, then returns "next".
func (m *machine[V]) String(out *string, next stateFn[V]) stateFn[V] {
	tok, err := m.Expect(kindString)
	if err != nil {
		return m.Error(err)
	}
	*out = tok.String()
	return next
}

// Text interprets the next [jsontext.Token] as an [encoding.TextUnmarshaler],
// stores it in the passed value, then returns "next".
func (m *machine[V]) Text(out encoding.TextUnmarshaler, next stateFn[V]) stateFn[V] {
	tok, err := m.Expect(kindString)
	if err != nil {
		return m.Error(err)
	}
	if err := out.UnmarshalText([]byte(tok.String())); err != nil {
		err = fmt.Errorf("at %s: %w", m.dec.StackPointer(), err)
		return m.Error(err)
	}
	return next
}

// DoArray stores a slice of "T" values into the provided address, then returns
// "next".
//
// A JSON "null" writes a nil slice into the provided address.
func doArray[V any, T any](m *machine[V], out *[]T, next stateFn[V]) stateFn[V] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}
	switch tok.Kind() {
	case kindArrayBegin:
		*out = make([]T, 0)
	case kindNull:
		*out = nil
		return next
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q: %w", m.dec.StackPointer(), tok, m.dec.SkipValue())
		return m.Error(err)
	}

	var arrayElem stateFn[V]
	arrayElem = func(m *machine[V]) stateFn[V] {
		if m.dec.PeekKind() == kindArrayEnd {
			m.dec.ReadToken()
			return next
		}
		var v T
		if err := json.UnmarshalDecode(m.dec, &v); err != nil {
			return m.Error(err)
		}
		*out = append(*out, v)
		return arrayElem
	}
	return arrayElem
}

// ObjectBegin returns a [stateFn] that returns "keys" if the next
// [jsontext.Token] is '{'.
//
// A JSON "null" returns a non-error terminal state.
func objectBegin[V any](keys stateFn[V]) stateFn[V] {
	return func(m *machine[V]) stateFn[V] {
		tok, err := m.dec.ReadToken()
		if err != nil {
			return m.Error(err)
		}
		switch k := tok.Kind(); k {
		case kindObjBegin:
			return keys
		case kindNull:
			return nil
		default:
			err := fmt.Errorf("unexpected token kind: got: %q, need: %q", k, jsontext.BeginObject)
			return m.Error(err)
		}
	}
}

// DoMap stores a map[string]T into the provided address, then returns
// "next".
//
// A JSON "null" writes a nil map into the provided address.
func doMap[V any, T any](m *machine[V], out *map[string]T, next stateFn[V]) stateFn[V] {
	typ := reflect.TypeFor[T]()
	needPtr := typ.Kind() == reflect.Pointer
	if needPtr {
		typ = typ.Elem()
	}

	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}
	switch tok.Kind() {
	case kindObjBegin:
		*out = make(map[string]T)
	case kindNull:
		*out = nil
		return next
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q: %w", m.dec.StackPointer(), tok, m.dec.SkipValue())
		return m.Error(err)
	}

	var mapKV stateFn[V]
	mapKV = func(m *machine[V]) stateFn[V] {
		tok, err := m.dec.ReadToken()
		if err != nil {
			return m.Error(err)
		}

		var key string
		switch k := tok.Kind(); k {
		case kindObjEnd:
			return next
		case kindString:
			key = tok.String()
		default:
			return m.Error(fmt.Errorf("unexpected token: %v", tok))
		}

		rv := reflect.New(typ)
		if err := json.UnmarshalDecode(m.dec, rv.Interface()); err != nil {
			return m.Error(err)
		}
		if !needPtr {
			rv = rv.Elem()
		}
		v, ok := reflect.TypeAssert[T](rv)
		if !ok {
			panic("unreachable: all the weirdness should be contained to this function")
		}
		(*out)[key] = v

		return mapKV
	}
	return mapKV
}
