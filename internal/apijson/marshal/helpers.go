package marshal

import "github.com/quay/clair/v4/internal/json/jsontext"

// DoMap handles a map value.
func doMap[T any](enc *jsontext.Encoder, t jsontext.Token, m map[string]*T, f func(*jsontext.Encoder, *T) error) error {
	if len(m) == 0 {
		return nil
	}
	if err := enc.WriteToken(t); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	for k, v := range m {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := f(enc, v); err != nil {
			return err
		}
	}
	return nil
}

// DoMapArray handles a map string-slice value.
func doMapArray[T any](enc *jsontext.Encoder, t jsontext.Token, m map[string][]T, f func(*jsontext.Encoder, T) error) error {
	if len(m) == 0 {
		return nil
	}
	if err := enc.WriteToken(t); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	writeArray := func(v []T) error {
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)
		for _, v := range v {
			if err := f(enc, v); err != nil {
				return err
			}
		}
		return nil
	}
	for k, v := range m {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := writeArray(v); err != nil {
			return err
		}
	}
	return nil
}
