// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package name provides methods for manipulating resource names.
package name

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ResourceKind is the type that will be used for all public resource kinds.
type ResourceKind string

const (
	// Position of projectID in name string
	projectKeywordIndex = 1
	// Position of the resourceID in the string
	resourceKeywordIndex = 3
	projectsKeyword      = "projects"
	occurrencesKeyword   = "occurrences"
	notesKeyword         = "notes"
	operationsKeyword    = "operations"

	// Note is the ResourceKind associated with notes.
	Note = ResourceKind(notesKeyword)
	// Occurrence is the ResourceKind associated with occurrences.
	Occurrence = ResourceKind(occurrencesKeyword)
	// Operation is the ResourceKind associated with operations.
	Operation = ResourceKind(operationsKeyword)
	// Unknown is the ResourceKind when the kind cannot be determined.
	Unknown = ResourceKind("")

	// NoCharLimit is used to signal that no resource id length validation is needed
	NoCharLimit = -1
)

var (
	projectNameFormat    = FormatProject("{project_id}")
	occurrenceNameFormat = FormatOccurrence("{project_id}", "{occurrence_id}")
	operationNameFormat  = FormatOperation("{provider_project_id}", "{operation_id}")
	noteNameFormat       = FormatNote("{provider_project_id}", "{note_id}")
)

func invalidArg(pattern, got string) error {
	return status.Error(codes.InvalidArgument, fmt.Sprintf("expected name to be of form %q, input was %v", pattern, got))
}

// FormatProject synthesizes a stringly typed name of the form:
//   projects/{project_id}
// See also: ParseProject
func FormatProject(projectID string) string {
	return fmt.Sprintf("%v/%v", projectsKeyword, projectID)
}

func OccurrenceName(pID, oID string) string {
	return fmt.Sprintf("projects/%v/occurrences/%v", pID, oID)
}

func OperationName(pID, oID string) string {
	return fmt.Sprintf("projects/%v/operations/%v", pID, oID)
}

func NoteName(pID, nID string) string {
	return fmt.Sprintf("projects/%v/notes/%v", pID, nID)
}

// FormatNoteProjectKW synthesizes a stringly typed name of the form:
//   projects/{project_id}/notes/{note_id}
// See also: ParseNote
func FormatNote(projectID, noteID string) string {
	return strings.Join([]string{projectsKeyword, projectID, string(Note), noteID}, "/")
}

// FormatOccurrence synthesizes a stringly typed name of the form:
//   projects/{project_id}/occurrences/{occurrence_id}
// See also: ParseOccurrence
func FormatOccurrence(projectID, occurrenceID string) string {
	return strings.Join([]string{projectsKeyword, projectID, string(Occurrence), occurrenceID}, "/")
}

// FormatOperation synthesizes a stringly typed name of the form:
//   providers/{provider_id}/project/{project_id}/operations/{operation_id}
// See also: ParseOperation
func FormatOperation(projectID, operationID string) string {
	return strings.Join([]string{projectsKeyword, projectID, operationsKeyword, operationID}, "/")
}

// ParseResourceKindAndResource takes a stringly typed name of the form:
//    projects/{project_id}/occurrences/{occurrence_id}
//    projects/{project_name}/notes/{note_id}
//    or:
// validates form and returns either an error or the ResourceKind
// (either occurrence or note) and project/resource-ids
func ParseResourceKindAndResource(name string) (ResourceKind, string, string, error) {
	err := invalidArg(fmt.Sprintf("%q or %q", occurrenceNameFormat, noteNameFormat), name)
	params := strings.Split(name, "/")
	if len(params) != 4 {
		return Unknown, "", "", err
	}
	switch params[projectKeywordIndex-1] {
	case projectsKeyword:
		switch params[resourceKeywordIndex-1] {
		case string(Occurrence):
			return Occurrence, params[projectKeywordIndex], params[resourceKeywordIndex], nil
		case string(Note):
			return Note, params[projectKeywordIndex], params[resourceKeywordIndex], nil
		case string(Operation):
			return Operation, params[projectKeywordIndex], params[resourceKeywordIndex], nil
		}

		return Unknown, "", "", invalidArg(fmt.Sprintf("%q or %q", occurrenceNameFormat, noteNameFormat), name)
	}
	return Unknown, "", "", err
}

// ParseResourceKindAndProjectFromPath retrieves a projectID and resource kind from a Grafeas URL path
// This method should be used with CreateRequests.
func ParseResourceKindAndProject(parent string) (ResourceKind, string, error) {
	err := invalidArg(fmt.Sprintf("%q or %q", occurrenceNameFormat, noteNameFormat), parent)
	params := strings.Split(parent, "/")
	if len(params) != 3 {
		return Unknown, "", err
	}

	switch params[projectKeywordIndex-1] {
	case projectsKeyword:
		switch params[resourceKeywordIndex-1] {
		case string(Occurrence):
			return Occurrence, params[projectKeywordIndex], nil
		case string(Note):
			return Note, params[projectKeywordIndex], nil
		case string(Operation):
			return Operation, params[projectKeywordIndex], nil
		}

		return Unknown, "", invalidArg(fmt.Sprintf("%q, %q, or %q", occurrenceNameFormat,
			noteNameFormat, operationNameFormat), parent)
	}
	return Unknown, "", err
}

// ParseOccurrence takes a stringly typed name of the form:
//   projects/{project_id}/occurrences/{occurrence_id}
// validates its form and returns either an error or the project-/occurrence-ids.
func ParseOccurrence(name string) (string, string, error) {
	return parseProjectAndEntityID(name, projectsKeyword, occurrencesKeyword, NoCharLimit)
}

// ParseNote takes a stringly typed name of the forms:
//   providers/{provider_name}/notes/{note_id}
// providers/{provider_name}/notes/{note_id}
// validates its form and returns either an error or the provider-/note-ids.
func ParseNote(name string) (string, string, error) {
	return parseProjectAndEntityID(name, projectsKeyword, notesKeyword, 100)
}

// ParseOperation takes a stringly typed name of the form:
//  projects/{project_id}/operations/{operation_id}
// validates its form and returns either an error or the project-/operation-ids
func ParseOperation(name string) (string, string, error) {
	return parseProjectAndEntityID(name, projectsKeyword, operationsKeyword, 100)
}

// parseProjectAndEntityID takes resource and project keywords, a max resource id length and a stringly typed name of the form:
//   projects/{project_id}/<resourceKeyword>/{entity_id}
// validates its form and returns either an error or the project and resource ids. Only validates maxResourceIDLength if it is greater than 0
func parseProjectAndEntityID(name, projectKeyword, resourceKeyword string, maxResourceIDLength int) (string, string, error) {
	format := fmt.Sprintf("%s/{project_id}/%s/{entity_id}", projectKeyword, resourceKeyword)
	params := strings.Split(name, "/")
	if len(params) != 4 {
		return "", "", invalidArg(format, name)
	}
	if params[projectKeywordIndex-1] != projectKeyword {
		return "", "", invalidArg(format, name)
	}
	if params[resourceKeywordIndex-1] != resourceKeyword {
		return "", "", invalidArg(format, name)
	}
	if params[projectKeywordIndex] == "" || params[resourceKeywordIndex] == "" {
		return "", "", invalidArg(format, name)
	}
	if maxResourceIDLength > 0 && len(params[resourceKeywordIndex]) > maxResourceIDLength {
		return "", "", status.Error(codes.InvalidArgument, fmt.Sprintf("resource id must be <= %v characters. Input was %v", maxResourceIDLength, name))
	}
	return params[projectKeywordIndex], params[resourceKeywordIndex], nil
}

// ParseProject takes a stringly typed name of the form:
//   projects/{project_id}
// validates its form and returns either an error or the project-id.
func ParseProject(name string) (string, error) {
	params := strings.Split(name, "/")
	if len(params) != 2 {
		return "", invalidArg(projectNameFormat, name)
	}
	if params[projectKeywordIndex-1] != projectsKeyword {
		return "", invalidArg(projectNameFormat, name)
	}
	if params[projectKeywordIndex] == "" {
		return "", invalidArg(projectNameFormat, name)
	}
	return params[projectKeywordIndex], nil
}
