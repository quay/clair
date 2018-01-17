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

package storage

import (
	"fmt"
	"strings"
	"sync"

	"github.com/grafeas/grafeas/samples/server/go-server/api/server/name"
	"github.com/grafeas/grafeas/server-go"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	opspb "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// memStore is an in-memory storage solution for Grafeas
type memStore struct {
	sync.RWMutex
	occurrencesByID map[string]*pb.Occurrence
	notesByID       map[string]*pb.Note
	opsByID         map[string]*opspb.Operation
	projects        map[string]bool
}

// NewMemStore creates a memStore with all maps initialized.
func NewMemStore() server.Storager {
	return &memStore{
		occurrencesByID: map[string]*pb.Occurrence{},
		notesByID:       map[string]*pb.Note{},
		opsByID:         map[string]*opspb.Operation{},
		projects:        map[string]bool{},
	}
}

// CreateProject adds the specified project to the mem store
func (m *memStore) CreateProject(pID string) error {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.projects[pID]; ok {
		return status.Error(codes.AlreadyExists, fmt.Sprintf("Project with name %q already exists", pID))
	}
	m.projects[pID] = true
	return nil
}

// DeleteProject deletes the project with the given pID from the mem store
func (m *memStore) DeleteProject(pID string) error {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.projects[pID]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Project with name %q does not Exist", pID))
	}
	delete(m.projects, pID)
	return nil
}

// GetProject returns the project with the given pID from the mem store
func (m *memStore) GetProject(pID string) (*pb.Project, error) {
	m.RLock()
	defer m.RUnlock()
	if _, ok := m.projects[pID]; !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Project with name %q does not Exist", pID))
	}
	return &pb.Project{Name: name.FormatProject(pID)}, nil
}

// ListProjects returns the project id for all projects from the mem store
func (m *memStore) ListProjects(filters string) []*pb.Project {
	m.RLock()
	defer m.RUnlock()
	projects := make([]*pb.Project, len(m.projects))
	i := 0
	for k := range m.projects {
		projects[i] = &pb.Project{Name: name.FormatProject(k)}
		i++
	}
	return projects
}

// CreateOccurrence adds the specified occurrence to the mem store
func (m *memStore) CreateOccurrence(o *pb.Occurrence) error {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.occurrencesByID[o.Name]; ok {
		return status.Error(codes.AlreadyExists, fmt.Sprintf("Occurrence with name %q already exists", o.Name))
	}
	m.occurrencesByID[o.Name] = o
	return nil
}

// DeleteOccurrence deletes the occurrence with the given pID and oID from the memStore
func (m *memStore) DeleteOccurrence(pID, oID string) error {
	oName := name.OccurrenceName(pID, oID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.occurrencesByID[oName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Occurrence with oName %q does not Exist", oName))
	}
	delete(m.occurrencesByID, oName)
	return nil
}

// UpdateOccurrence updates the existing occurrence with the given projectID and occurrenceID
func (m *memStore) UpdateOccurrence(pID, oID string, o *pb.Occurrence) error {
	oName := name.OccurrenceName(pID, oID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.occurrencesByID[oName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Occurrence with oName %q does not Exist", oName))
	}
	m.occurrencesByID[oName] = o
	return nil
}

// GetOccurrence returns the occurrence with pID and oID
func (m *memStore) GetOccurrence(pID, oID string) (*pb.Occurrence, error) {
	oName := name.OccurrenceName(pID, oID)
	m.RLock()
	defer m.RUnlock()
	o, ok := m.occurrencesByID[oName]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Occurrence with name %q does not Exist", oName))
	}
	return o, nil
}

// ListOccurrences returns the occurrences for this project ID (pID)
func (m *memStore) ListOccurrences(pID, filters string) []*pb.Occurrence {
	os := []*pb.Occurrence{}
	m.RLock()
	defer m.RUnlock()
	for _, o := range m.occurrencesByID {
		if strings.HasPrefix(o.Name, fmt.Sprintf("projects/%v", pID)) {
			os = append(os, o)
		}
	}
	return os
}

// CreateNote adds the specified note to the mem store
func (m *memStore) CreateNote(n *pb.Note) error {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.notesByID[n.Name]; ok {
		return status.Error(codes.AlreadyExists, fmt.Sprintf("Note with name %q already exists", n.Name))
	}
	m.notesByID[n.Name] = n
	return nil
}

// DeleteNote deletes the note with the given pID and nID from the memStore
func (m *memStore) DeleteNote(pID, nID string) error {
	nName := name.NoteName(pID, nID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.notesByID[nName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Note with name %q does not Exist", nName))
	}
	delete(m.notesByID, nName)
	return nil
}

// UpdateNote updates the existing note with the given pID and nID
func (m *memStore) UpdateNote(pID, nID string, n *pb.Note) error {
	nName := name.NoteName(pID, nID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.notesByID[nName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Note with name %q does not Exist", nName))
	}
	m.notesByID[nName] = n
	return nil
}

// GetNote returns the note with pID and nID
func (m *memStore) GetNote(pID, nID string) (*pb.Note, error) {
	nName := name.NoteName(pID, nID)
	m.RLock()
	defer m.RUnlock()
	n, ok := m.notesByID[nName]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Note with name %q does not Exist", nName))
	}
	return n, nil
}

// GetNoteByOccurrence returns the note attached to occurrence with pID and oID
func (m *memStore) GetNoteByOccurrence(pID, oID string) (*pb.Note, error) {
	oName := name.OccurrenceName(pID, oID)
	m.RLock()
	defer m.RUnlock()
	o, ok := m.occurrencesByID[oName]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Occurrence with name %q does not Exist", oName))
	}
	n, ok := m.notesByID[o.NoteName]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Note with name %q does not Exist", o.NoteName))
	}
	return n, nil
}

// ListNotes returns the notes for for this project (pID)
func (m *memStore) ListNotes(pID, filters string) []*pb.Note {
	ns := []*pb.Note{}
	m.RLock()
	defer m.RUnlock()
	for _, n := range m.notesByID {
		if strings.HasPrefix(n.Name, fmt.Sprintf("projects/%v", pID)) {
			ns = append(ns, n)
		}
	}
	return ns
}

// ListNoteOccurrences returns the occcurrences on the particular note (nID) for this project (pID)
func (m *memStore) ListNoteOccurrences(pID, nID, filters string) ([]*pb.Occurrence, error) {
	// TODO: use filters
	m.RLock()
	defer m.RUnlock()
	// Verify that note exists
	if _, err := m.GetNote(pID, nID); err != nil {
		return nil, err
	}
	nName := name.FormatNote(pID, nID)
	os := []*pb.Occurrence{}
	for _, o := range m.occurrencesByID {
		if o.NoteName == nName {
			os = append(os, o)
		}
	}
	return os, nil
}

// GetOperation returns the operation with pID and oID
func (m *memStore) GetOperation(pID, opID string) (*opspb.Operation, error) {
	oName := name.OperationName(pID, opID)
	m.RLock()
	defer m.RUnlock()
	o, ok := m.opsByID[oName]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q does not Exist", oName))
	}
	return o, nil
}

// CreateOperation adds the specified operation to the mem store
func (m *memStore) CreateOperation(o *opspb.Operation) error {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.opsByID[o.Name]; ok {
		return status.Error(codes.AlreadyExists, fmt.Sprintf("Operation with name %q already exists", o.Name))
	}
	m.opsByID[o.Name] = o
	return nil
}

// DeleteOperation deletes the operation with the given pID and oID from the memStore
func (m *memStore) DeleteOperation(pID, opID string) error {
	opName := name.OperationName(pID, opID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.opsByID[opName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q does not Exist", opName))
	}
	delete(m.occurrencesByID, opName)
	return nil
}

// UpdateOperation updates the existing operation with the given pID and nID
func (m *memStore) UpdateOperation(pID, opID string, op *opspb.Operation) error {
	opName := name.OperationName(pID, opID)
	m.Lock()
	defer m.Unlock()
	if _, ok := m.opsByID[opName]; !ok {
		return status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q does not Exist", opName))
	}
	m.opsByID[opName] = op
	return nil
}

// ListOperations returns the operations for this project (pID)
func (m *memStore) ListOperations(pID, filters string) []*opspb.Operation {
	ops := []*opspb.Operation{}
	m.RLock()
	defer m.RUnlock()
	for _, op := range m.opsByID {
		if strings.HasPrefix(op.Name, fmt.Sprintf("projects/%v", pID)) {
			ops = append(ops, op)
		}
	}
	return ops
}
