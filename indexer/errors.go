package indexer

import "fmt"

// IndexStartErr indicates an index operation failed to start
type ErrIndexStart struct {
	e error
}

func (e *ErrIndexStart) Error() string {
	return e.e.Error()
}

// ErrIndexReportNotFound indicates a requested IndexReport was not found
type ErrIndexReportNotFound struct {
	hash string
}

func (e *ErrIndexReportNotFound) Error() string {
	return fmt.Sprintf("failed to find manifest: %v", e.hash)
}

// ErrIndexReportRetrieval indicates an error while attempting to retrieve an IndexReport
type ErrIndexReportRetrieval struct {
	e error
}

func (e *ErrIndexReportRetrieval) Error() string {
	return e.e.Error()
}
