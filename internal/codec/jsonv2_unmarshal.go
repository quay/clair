package codec

import (
	"encoding"
	"fmt"
	"reflect"

	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

type unmarshalMachine[V any] struct {
	dec   *jsontext.Decoder
	out   *V
	err   error
	state uStateFn[V]
}

type uStateFn[V any] func(*unmarshalMachine[V]) uStateFn[V]

func runUnmarshalMachine[V any](dec *jsontext.Decoder, out *V, init uStateFn[V]) error {
	m := unmarshalMachine[V]{
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

func (m *unmarshalMachine[V]) error(err error) uStateFn[V] {
	m.err = err
	return nil
}

func (m *unmarshalMachine[V]) invalidObjectKey() uStateFn[V] {
	m.err = fmt.Errorf("invalid object key (at %s)", m.dec.StackPointer())
	return nil
}

func (m *unmarshalMachine[V]) expectKind(want jsontext.Kind) (jsontext.Token, error) {
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

func unmarshalArray[V any, T any](m *unmarshalMachine[V], out *[]T, after uStateFn[V]) uStateFn[V] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}
	switch tok.Kind() {
	case '[':
		*out = make([]T, 0)
	case 'n':
		out = nil
		return after
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q: %w", m.dec.StackPointer(), tok, m.dec.SkipValue())
		return m.error(err)
	}

	var arrayElem uStateFn[V]
	arrayElem = func(m *unmarshalMachine[V]) uStateFn[V] {
		if m.dec.PeekKind() == ']' {
			m.dec.ReadToken()
			return after
		}
		var v T
		if err := json.UnmarshalDecode(m.dec, &v); err != nil {
			return m.error(err)
		}
		*out = append(*out, v)
		return arrayElem
	}
	return arrayElem
}

func unmarshalObjectBegin[V any](keys uStateFn[V]) uStateFn[V] {
	return func(m *unmarshalMachine[V]) uStateFn[V] {
		tok, err := m.dec.ReadToken()
		if err != nil {
			return m.error(err)
		}
		switch k := tok.Kind(); k {
		case '{':
			return keys
		case 'n':
			return nil
		default:
			err := fmt.Errorf("unexpected token kind: got: %q, need: %q", k, jsontext.BeginObject)
			return m.error(err)
		}
	}
}

func unmarshalMap[V any, T any](m *unmarshalMachine[V], out *map[string]T, after uStateFn[V]) uStateFn[V] {
	typ := reflect.TypeFor[T]()
	needPtr := typ.Kind() == reflect.Pointer
	if needPtr {
		typ = typ.Elem()
	}

	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}
	switch tok.Kind() {
	case '{':
		*out = make(map[string]T)
	case 'n':
		out = nil
		return after
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q: %w", m.dec.StackPointer(), tok, m.dec.SkipValue())
		return m.error(err)
	}

	var mapKV uStateFn[V]
	mapKV = func(m *unmarshalMachine[V]) uStateFn[V] {
		tok, err := m.dec.ReadToken()
		if err != nil {
			return m.error(err)
		}

		var key string
		switch k := tok.Kind(); k {
		case '}':
			return after
		case '"':
			key = tok.String()
		default:
			return m.error(fmt.Errorf("unexpected token: %v", tok))
		}

		rv := reflect.New(typ)
		if err := json.UnmarshalDecode(m.dec, rv.Interface()); err != nil {
			return m.error(err)
		}
		if !needPtr {
			rv = rv.Elem()
		}
		v, ok := rv.Interface().(T)
		// TODO(go1.25) This should be more efficient:
		// v, ok := reflect.TypeAssert[T](rv)
		if !ok {
			panic("unreachable: all the weirdness should be contained to this function")
		}
		(*out)[key] = v

		return mapKV
	}
	return mapKV
}

func (m *unmarshalMachine[V]) doBool(out *bool, next uStateFn[V]) uStateFn[V] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}
	switch tok.Kind() {
	case 't', 'f':
	default:
		err := fmt.Errorf("unexpected token (at %s): got %q, want %q: %w", m.dec.StackPointer(), tok, "t/f", m.dec.SkipValue())
		return m.error(err)
	}
	*out = tok.Bool()
	return next
}

func (m *unmarshalMachine[V]) doString(out *string, next uStateFn[V]) uStateFn[V] {
	tok, err := m.expectKind(jsontext.Kind('"'))
	if err != nil {
		return m.error(err)
	}
	*out = tok.String()
	return next
}

func (m *unmarshalMachine[V]) doText(out encoding.TextUnmarshaler, next uStateFn[V]) uStateFn[V] {
	tok, err := m.expectKind(jsontext.Kind('"'))
	if err != nil {
		return m.error(err)
	}
	if err := out.UnmarshalText([]byte(tok.String())); err != nil {
		err = fmt.Errorf("at %s: %w", m.dec.StackPointer(), err)
		return m.error(err)
	}
	return next
}
