package clair

import "errors"

const oSNotSupportedValue = "worker: OS and/or package manager are not supported"

var (
	OSNotSupported = errors.New(oSNotSupportedValue)
)

type LayerError struct {
	Message string
}
