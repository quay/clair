// Package apijson holds machinery for working with the v1 HTTP API types.
package apijson

import (
	"github.com/quay/clair/v4/internal/apijson/marshal"
	"github.com/quay/clair/v4/internal/apijson/unmarshal"
	"github.com/quay/clair/v4/internal/json"
)

// Options is a [json.Options] that should be used for [json.Marshal] or
// [json.Unmarshal] calls that handle v1 HTTP API types.
var Options = json.JoinOptions(
	json.WithMarshalers(Marshalers),
	json.WithUnmarshalers(Unmarshalers),
)

// Marshalers is the set of marshal functions for the v1 HTTP API types.
var Marshalers = json.JoinMarshalers(
	// API-only types:
	json.MarshalToFunc(marshal.Error),
	// Indexer types:
	json.MarshalToFunc(marshal.Manifest),
	json.MarshalToFunc(marshal.Layer),
	json.MarshalToFunc(marshal.IndexReport),
	json.MarshalToFunc(marshal.Package),
	json.MarshalToFunc(marshal.Repository),
	json.MarshalToFunc(marshal.Distribution),
	json.MarshalToFunc(marshal.Environment),
	// Matcher types:
	json.MarshalToFunc(marshal.VulnerabilityReport),
	json.MarshalToFunc(marshal.Vulnerability),
	json.MarshalToFunc(marshal.Range),
	json.MarshalToFunc(marshal.UpdateOperation),
	json.MarshalToFunc(marshal.UpdateDiff),
)

// Unmarshalers is the set of unmarshal functions for the v1 HTTP API types.
var Unmarshalers = json.JoinUnmarshalers(
	// Indexer types:
	json.UnmarshalFromFunc(unmarshal.Manifest),
	json.UnmarshalFromFunc(unmarshal.Layer),
	json.UnmarshalFromFunc(unmarshal.IndexReport),
	json.UnmarshalFromFunc(unmarshal.Package),
	json.UnmarshalFromFunc(unmarshal.Distribution),
	json.UnmarshalFromFunc(unmarshal.Repository),
	json.UnmarshalFromFunc(unmarshal.Environment),
	json.UnmarshalFromFunc(unmarshal.VulnerabilityReport),
	json.UnmarshalFromFunc(unmarshal.Vulnerability),
	json.UnmarshalFromFunc(unmarshal.Range),
)
