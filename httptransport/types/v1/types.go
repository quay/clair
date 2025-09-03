// Package types provides JSON Schemas for the HTTP API.
package types

import (
	"embed"
)

//go:generate sh -euc "for f in *.json; do <$DOLLAR{f} >$DOLLAR{f}_ jq -e .; mv $DOLLAR{f}_ $DOLLAR{f}; done"

//go:embed *.schema.json
var Schema embed.FS
