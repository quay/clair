package clairerror

import (
	"fmt"

	"github.com/google/uuid"
)

// ErrRequestFail indicates an http request failure
type ErrRequestFail struct {
	Code   int
	Status string
}

func (e *ErrRequestFail) Error() string {
	return fmt.Sprintf("code: %v status %v", e.Code, e.Status)
}

// ErrBadManifest inidcates a manifest could not be parsed
type ErrBadManifest struct {
	E error
}

func (e *ErrBadManifest) Error() string {
	return e.E.Error()
}

func (e *ErrBadManifest) Unwrap() error {
	return e.E
}

// ErrBadManifest inidcates a manifest could not be parsed
type ErrBadIndexReport struct {
	E error
}

func (e *ErrBadIndexReport) Error() string {
	return e.E.Error()
}

func (e *ErrBadIndexReport) Unwrap() error {
	return e.E
}

// IndexStartErr indicates an index operation failed to start
type ErrIndexStart struct {
	E error
}

func (e *ErrIndexStart) Error() string {
	return e.E.Error()
}

func (e *ErrIndexStart) Unwrap() error {
	return e.E
}

// ErrIndexReportNotFound indicates a requested IndexReport was not found
type ErrIndexReportNotFound struct {
	Hash string
}

func (e *ErrIndexReportNotFound) Error() string {
	return fmt.Sprintf("failed to find manifest: %v", e.Hash)
}

// ErrIndexReportRetrieval indicates an error while attempting to retrieve an IndexReport
type ErrIndexReportRetrieval struct {
	E error
}

func (e *ErrIndexReportRetrieval) Error() string {
	return e.E.Error()
}

func (e *ErrIndexReportRetrieval) Unwrap() error {
	return e.E
}

// ErrMatch indicates an issue with matching a IndexReport to a VulnerabilityReport
type ErrMatch struct {
	E error
}

func (e *ErrMatch) Error() string {
	return e.E.Error()
}

func (e *ErrMatch) Unwrap() error {
	return e.E
}

// ErrNotInitialized indicates an issue with initialization.
type ErrNotInitialized struct {
	Msg string
}

func (e ErrNotInitialized) Error() string {
	return e.Msg
}

// ErrBadVulnerabilities indicates an issue where a set of Vulnerabilities could not be marshalled or unmarshalled
// into JSON.
type ErrBadVulnerabilities struct {
	E error
}

func (e *ErrBadVulnerabilities) Error() string {
	return e.E.Error()
}

func (e *ErrBadVulnerabilities) Unwrap() error {
	return e.E
}

// ErrBadAffectedManifests indicates an issue where an AffectedManifests could not be marshalled or unmarshalled
// into JSON.
type ErrBadAffectedManifests struct {
	E error
}

func (e *ErrBadAffectedManifests) Error() string {
	return e.E.Error()
}

func (e *ErrBadAffectedManifests) Unwrap() error {
	return e.E
}

type ErrKeyNotFound struct {
	ID uuid.UUID
}

func (e ErrKeyNotFound) Error() string {
	return "key with id " + e.ID.String() + " not found"
}
