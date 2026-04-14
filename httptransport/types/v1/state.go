package types

// IndexState is a concrete type for
// https://clairproject.org/api/http/v1/index_state.schema.json.
type IndexState struct {
	State string
}

// NewIndexState constructs an [IndexState].
func NewIndexState(tok string) *IndexState {
	return &IndexState{State: tok}
}
