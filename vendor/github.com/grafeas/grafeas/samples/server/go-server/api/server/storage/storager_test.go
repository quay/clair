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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/grafeas/grafeas/samples/server/go-server/api/server/name"
	"github.com/grafeas/grafeas/samples/server/go-server/api/server/testing"
	server "github.com/grafeas/grafeas/server-go"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	opspb "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Tests implementations of server.Storager
// createStore is a function that creates new server.Storage instances and
// a corresponding cleanUp function that will be run at the end of each
// test case.
func doTestStorager(t *testing.T, createStore func(t *testing.T) (server.Storager, func())) {
	t.Run("CreateProject", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		p := "myproject"
		if err := s.CreateProject(p); err != nil {
			t.Errorf("CreateProject got %v want success", err)
		}
		// Try to insert the same project twice, expect failure.
		if err := s.CreateProject(p); err == nil {
			t.Errorf("CreateProject got success, want Error")
		} else if s, _ := status.FromError(err); s.Code() != codes.AlreadyExists {
			t.Errorf("CreateProject got code %v want %v", s.Code(), codes.AlreadyExists)
		}
	})

	t.Run("CreateNote", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Errorf("CreateNote got %v want success", err)
		}
		// Try to insert the same note twice, expect failure.
		if err := s.CreateNote(n); err == nil {
			t.Errorf("CreateNote got success, want Error")
		} else if s, _ := status.FromError(err); s.Code() != codes.AlreadyExists {
			t.Errorf("CreateNote got code %v want %v", s.Code(), codes.AlreadyExists)
		}
	})

	t.Run("CreateOccurrence", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		oPID := "occurrence-project"
		o := testutil.Occurrence(oPID, n.Name)
		if err := s.CreateOccurrence(o); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		// Try to insert the same occurrence twice, expect failure.
		if err := s.CreateOccurrence(o); err == nil {
			t.Errorf("CreateOccurrence got success, want Error")
		} else if s, _ := status.FromError(err); s.Code() != codes.AlreadyExists {
			t.Errorf("CreateOccurrence got code %v want %v", s.Code(), codes.AlreadyExists)
		}
		pID, oID, err := name.ParseOccurrence(o.Name)
		if err != nil {
			t.Fatalf("Error parsing projectID and occurrenceID %v", err)
		}
		if got, err := s.GetOccurrence(pID, oID); err != nil {
			t.Fatalf("GetOccurrence got %v, want success", err)
		} else if !reflect.DeepEqual(got, o) {
			t.Errorf("GetOccurrence got %v, want %v", got, o)
		}
	})

	t.Run("CreateOperation", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		opPID := "vulnerability-scanner-a"
		op := testutil.Operation(opPID)
		if err := s.CreateOperation(op); err != nil {
			t.Errorf("CreateOperation got %v want success", err)
		}
		// Try to insert the same note twice, expect failure.
		if err := s.CreateOperation(op); err == nil {
			t.Errorf("CreateOperation got success, want Error")
		} else if s, _ := status.FromError(err); s.Code() != codes.AlreadyExists {
			t.Errorf("CreateOperation got code %v want %v", s.Code(), codes.AlreadyExists)
		}
	})

	t.Run("DeleteProject", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "myproject"
		// Delete before the note exists
		if err := s.DeleteProject(pID); err == nil {
			t.Error("Deleting nonexistant note got success, want error")
		}
		if err := s.CreateProject(pID); err != nil {
			t.Fatalf("CreateProject got %v want success", err)
		}

		if err := s.DeleteProject(pID); err != nil {
			t.Errorf("DeleteProject got %v, want success ", err)
		}
	})

	t.Run("DeleteOccurrence", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		oPID := "occurrence-project"
		o := testutil.Occurrence(oPID, n.Name)
		// Delete before the occurrence exists
		pID, oID, err := name.ParseOccurrence(o.Name)
		if err != nil {
			t.Fatalf("Error parsing occurrence %v", err)
		}
		if err := s.DeleteOccurrence(pID, oID); err == nil {
			t.Error("Deleting nonexistant occurrence got success, want error")
		}
		if err := s.CreateOccurrence(o); err != nil {
			t.Fatalf("CreateOccurrence got %v want success", err)
		}
		if err := s.DeleteOccurrence(pID, oID); err != nil {
			t.Errorf("DeleteOccurrence got %v, want success ", err)
		}
	})

	t.Run("UpdateOccurrence", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		oPID := "occurrence-project"
		o := testutil.Occurrence(oPID, n.Name)
		pID, oID, err := name.ParseOccurrence(o.Name)
		if err != nil {
			t.Fatalf("Error parsing projectID and occurrenceID %v", err)
		}
		if err := s.UpdateOccurrence(pID, oID, o); err == nil {
			t.Fatal("UpdateOccurrence got success want error")
		}
		if err := s.CreateOccurrence(o); err != nil {
			t.Fatalf("CreateOccurrence got %v want success", err)
		}
		if got, err := s.GetOccurrence(pID, oID); err != nil {
			t.Fatalf("GetOccurrence got %v, want success", err)
		} else if !reflect.DeepEqual(got, o) {
			t.Errorf("GetOccurrence got %v, want %v", got, o)
		}

		o2 := o
		o2.GetVulnerabilityDetails().CvssScore = 1.0
		if err := s.UpdateOccurrence(pID, oID, o2); err != nil {
			t.Fatalf("UpdateOccurrence got %v want success", err)
		}

		if got, err := s.GetOccurrence(pID, oID); err != nil {
			t.Fatalf("GetOccurrence got %v, want success", err)
		} else if !reflect.DeepEqual(got, o2) {
			t.Errorf("GetOccurrence got %v, want %v", got, o2)
		}
	})

	t.Run("DeleteNote", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		// Delete before the note exists
		pID, oID, err := name.ParseNote(n.Name)
		if err != nil {
			t.Fatalf("Error parsing note %v", err)
		}
		if err := s.DeleteNote(pID, oID); err == nil {
			t.Error("Deleting nonexistant note got success, want error")
		}
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}

		if err := s.DeleteNote(pID, oID); err != nil {
			t.Errorf("DeleteNote got %v, want success ", err)
		}
	})

	t.Run("UpdateNote", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)

		pID, nID, err := name.ParseNote(n.Name)
		if err != nil {
			t.Fatalf("Error parsing projectID and noteID %v", err)
		}
		if err := s.UpdateNote(pID, nID, n); err == nil {
			t.Fatal("UpdateNote got success want error")
		}
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		if got, err := s.GetNote(pID, nID); err != nil {
			t.Fatalf("GetNote got %v, want success", err)
		} else if !reflect.DeepEqual(got, n) {
			t.Errorf("GetNote got %v, want %v", got, n)
		}

		n2 := n
		n2.GetVulnerabilityType().CvssScore = 1.0
		if err := s.UpdateNote(pID, nID, n2); err != nil {
			t.Fatalf("UpdateNote got %v want success", err)
		}

		if got, err := s.GetNote(pID, nID); err != nil {
			t.Fatalf("GetNote got %v, want success", err)
		} else if !reflect.DeepEqual(got, n2) {
			t.Errorf("GetNote got %v, want %v", got, n2)
		}
	})

	t.Run("GetProject", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "myproject"
		// Try to get project before it has been created, expect failure.
		if _, err := s.GetProject(pID); err == nil {
			t.Errorf("GetProject got success, want Error")
		} else if s, _ := status.FromError(err); s.Code() != codes.NotFound {
			t.Errorf("GetProject got code %v want %v", s.Code(), codes.NotFound)
		}
		s.CreateProject(pID)
		if p, err := s.GetProject(pID); err != nil {
			t.Fatalf("GetProject got %v want success", err)
		} else if p.Name != name.FormatProject(pID) {
			t.Fatalf("Got %s want %s", p.Name, pID)
		}
	})

	t.Run("GetOccurrence", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		oPID := "occurrence-project"
		o := testutil.Occurrence(oPID, n.Name)
		pID, oID, err := name.ParseOccurrence(o.Name)
		if err != nil {
			t.Fatalf("Error parsing occurrence %v", err)
		}
		if _, err := s.GetOccurrence(pID, oID); err == nil {
			t.Fatal("GetOccurrence got success, want error")
		}
		if err := s.CreateOccurrence(o); err != nil {
			t.Errorf("CreateOccurrence got %v, want Success", err)
		}
		if got, err := s.GetOccurrence(pID, oID); err != nil {
			t.Fatalf("GetOccurrence got %v, want success", err)
		} else if !reflect.DeepEqual(got, o) {
			t.Errorf("GetOccurrence got %v, want %v", got, o)
		}
	})

	t.Run("GetNote", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)

		pID, nID, err := name.ParseNote(n.Name)
		if err != nil {
			t.Fatalf("Error parsing note %v", err)
		}
		if _, err := s.GetNote(pID, nID); err == nil {
			t.Fatal("GetNote got success, want error")
		}
		if err := s.CreateNote(n); err != nil {
			t.Errorf("CreateNote got %v, want Success", err)
		}
		if got, err := s.GetNote(pID, nID); err != nil {
			t.Fatalf("GetNote got %v, want success", err)
		} else if !reflect.DeepEqual(got, n) {
			t.Errorf("GetNote got %v, want %v", got, n)
		}
	})

	t.Run("GetNoteByOccurrence", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		oPID := "occurrence-project"
		o := testutil.Occurrence(oPID, n.Name)
		pID, oID, err := name.ParseOccurrence(o.Name)
		if err != nil {
			t.Fatalf("Error parsing occurrence %v", err)
		}
		if _, err := s.GetNoteByOccurrence(pID, oID); err == nil {
			t.Fatal("GetNoteByOccurrence got success, want error")
		}
		if err := s.CreateOccurrence(o); err != nil {
			t.Errorf("CreateOccurrence got %v, want Success", err)
		}
		if got, err := s.GetNoteByOccurrence(pID, oID); err != nil {
			t.Fatalf("GetNoteByOccurrence got %v, want success", err)
		} else if !reflect.DeepEqual(got, n) {
			t.Errorf("GetNoteByOccurrence got %v, want %v", got, n)
		}
	})

	t.Run("GetOperation", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		oPID := "vulnerability-scanner-a"
		o := testutil.Operation(oPID)

		pID, oID, err := name.ParseOperation(o.Name)
		if err != nil {
			t.Fatalf("Error parsing operation %v", err)
		}
		if _, err := s.GetOperation(pID, oID); err == nil {
			t.Fatal("GetOperation got success, want error")
		}
		if err := s.CreateOperation(o); err != nil {
			t.Errorf("CreateOperation got %v, want Success", err)
		}
		if got, err := s.GetOperation(pID, oID); err != nil {
			t.Fatalf("GetOperation got %v, want success", err)
		} else if !reflect.DeepEqual(got, o) {
			t.Errorf("GetOperation got %v, want %v", got, o)
		}
	})

	t.Run("DeleteOperation", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		oPID := "vulnerability-scanner-a"
		o := testutil.Operation(oPID)
		// Delete before the operation exists
		pID, oID, err := name.ParseOperation(o.Name)
		if err != nil {
			t.Fatalf("Error parsing note %v", err)
		}
		if err := s.DeleteOperation(pID, oID); err == nil {
			t.Error("Deleting nonexistant operation got success, want error")
		}
		if err := s.CreateOperation(o); err != nil {
			t.Fatalf("CreateOperation got %v want success", err)
		}

		if err := s.DeleteOperation(pID, oID); err != nil {
			t.Errorf("DeleteOperation got %v, want success ", err)
		}
	})

	t.Run("UpdateOperation", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		oPID := "vulnerability-scanner-a"
		o := testutil.Operation(oPID)

		pID, oID, err := name.ParseOperation(o.Name)
		if err != nil {
			t.Fatalf("Error parsing projectID and operationID %v", err)
		}
		if err := s.UpdateOperation(pID, oID, o); err == nil {
			t.Fatal("UpdateOperation got success want error")
		}
		if err := s.CreateOperation(o); err != nil {
			t.Fatalf("CreateOperation got %v want success", err)
		}
		if got, err := s.GetOperation(pID, oID); err != nil {
			t.Fatalf("GetOperation got %v, want success", err)
		} else if !reflect.DeepEqual(got, o) {
			t.Errorf("GetOperation got %v, want %v", got, o)
		}

		o2 := o
		o2.Done = true
		if err := s.UpdateOperation(pID, oID, o2); err != nil {
			t.Fatalf("UpdateOperation got %v want success", err)
		}

		if got, err := s.GetOperation(pID, oID); err != nil {
			t.Fatalf("GetOperation got %v, want success", err)
		} else if !reflect.DeepEqual(got, o2) {
			t.Errorf("GetOperation got %v, want %v", got, o2)
		}
	})

	t.Run("ListProjects", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		wantProjectNames := []string{}
		for i := 0; i < 20; i++ {
			pID := fmt.Sprint("Project", i)
			if err := s.CreateProject(pID); err != nil {
				t.Fatalf("CreateProject got %v want success", err)
			}
			wantProjectNames = append(wantProjectNames, name.FormatProject(pID))
		}
		filter := "filters_are_yet_to_be_implemented"
		gotProjects, _, err := s.ListProjects(filter, 100, "")
		if err != nil {
			t.Fatalf("ListProjects got %v want success", err)
		}
		if len(gotProjects) != 20 {
			t.Errorf("ListProjects got %v projects, want 20", len(gotProjects))
		}
		gotProjectNames := make([]string, len(gotProjects))
		for i, project := range gotProjects {
			gotProjectNames[i] = project.Name
		}
		// Sort to handle that wantProjectNames are not guaranteed to be listed in insertion order
		sort.Strings(wantProjectNames)
		sort.Strings(gotProjectNames)
		if !reflect.DeepEqual(gotProjectNames, wantProjectNames) {
			t.Errorf("ListProjects got %v want %v", gotProjectNames, wantProjectNames)
		}
	})

	t.Run("ListOperations", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		ops := []opspb.Operation{}
		findProject := "findThese"
		dontFind := "dontFind"
		for i := 0; i < 20; i++ {
			o := testutil.Operation("")
			if i < 5 {
				o.Name = name.FormatOperation(findProject, strconv.Itoa(i))
			} else {
				o.Name = name.FormatOperation(dontFind, strconv.Itoa(i))
			}
			if err := s.CreateOperation(o); err != nil {
				t.Fatalf("CreateOperation got %v want success", err)
			}
			ops = append(ops, *o)
		}
		gotOs, _, err := s.ListOperations(findProject, "", 100, "")
		if err != nil {
			t.Fatalf("ListOperations got %v want success", err)
		}

		if len(gotOs) != 5 {
			t.Errorf("ListOperations got %v operations, want 5", len(gotOs))
		}
		for _, o := range gotOs {
			want := name.FormatProject(findProject)
			if !strings.HasPrefix(o.Name, want) {
				t.Errorf("ListOperations got %v want prefix %v", o.Name, want)
			}
		}
	})

	t.Run("ListNotes", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		ns := []*pb.Note{}
		findProject := "findThese"
		dontFind := "dontFind"
		for i := 0; i < 20; i++ {
			n := testutil.Note("")
			if i < 5 {
				n.Name = name.FormatNote(findProject, strconv.Itoa(i))
			} else {
				n.Name = name.FormatNote(dontFind, strconv.Itoa(i))
			}
			if err := s.CreateNote(n); err != nil {
				t.Fatalf("CreateNote got %v want success", err)
			}
			ns = append(ns, n)
		}
		gotNs, _, err := s.ListNotes(findProject, "", 100, "")
		if err != nil {
			t.Fatalf("ListNotes got %v want success", err)
		}
		if len(gotNs) != 5 {
			t.Errorf("ListNotes got %v notes, want 5", len(gotNs))
		}
		for _, n := range gotNs {
			want := name.FormatProject(findProject)
			if !strings.HasPrefix(n.Name, want) {
				t.Errorf("ListNotes got %v want %v", n.Name, want)
			}
		}
	})

	t.Run("ListOccurrences", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		os := []*pb.Occurrence{}
		findProject := "findThese"
		dontFind := "dontFind"
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		for i := 0; i < 20; i++ {
			oPID := "_"
			o := testutil.Occurrence(oPID, n.Name)
			if i < 5 {
				o.Name = name.FormatOccurrence(findProject, strconv.Itoa(i))
			} else {
				o.Name = name.FormatOccurrence(dontFind, strconv.Itoa(i))
			}
			if err := s.CreateOccurrence(o); err != nil {
				t.Fatalf("CreateOccurrence got %v want success", err)
			}
			os = append(os, o)
		}
		gotOs, _, err := s.ListOccurrences(findProject, "", 100, "")
		if err != nil {
			t.Fatalf("ListOccurrences got %v want success", err)
		}
		if len(gotOs) != 5 {
			t.Errorf("ListOccurrences got %v Occurrences, want 5", len(gotOs))
		}
		for _, o := range gotOs {
			want := name.FormatProject(findProject)
			if !strings.HasPrefix(o.Name, want) {
				t.Errorf("ListOccurrences got %v want  %v", o.Name, want)
			}
		}
	})

	t.Run("ListNoteOccurrences", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		os := []*pb.Occurrence{}
		findProject := "findThese"
		dontFind := "dontFind"
		nPID := "vulnerability-scanner-a"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		for i := 0; i < 20; i++ {
			oPID := "_"
			o := testutil.Occurrence(oPID, n.Name)
			if i < 5 {
				o.Name = name.FormatOccurrence(findProject, strconv.Itoa(i))
			} else {
				o.Name = name.FormatOccurrence(dontFind, strconv.Itoa(i))
			}
			if err := s.CreateOccurrence(o); err != nil {
				t.Fatalf("CreateOccurrence got %v want success", err)
			}
			os = append(os, o)
		}
		pID, nID, err := name.ParseNote(n.Name)
		if err != nil {
			t.Fatalf("Error parsing note name %v", err)
		}
		gotOs, _, err := s.ListNoteOccurrences(pID, nID, "", 100, "")
		if err != nil {
			t.Fatalf("ListNoteOccurrences got %v want success", err)
		}
		if len(gotOs) != 20 {
			t.Errorf("ListNoteOccurrences got %v Occurrences, want 20", len(gotOs))
		}
		for _, o := range gotOs {
			if o.NoteName != n.Name {
				t.Errorf("ListNoteOccurrences got %v want  %v", o.Name, o.NoteName)
			}
		}
	})

	t.Run("ProjectPagination", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID1 := "project1"
		if err := s.CreateProject(pID1); err != nil {
			t.Errorf("CreateProject got %v want success", err)
		}
		pID2 := "project2"
		if err := s.CreateProject(pID2); err != nil {
			t.Errorf("CreateProject got %v want success", err)
		}
		pID3 := "project3"
		if err := s.CreateProject(pID3); err != nil {
			t.Errorf("CreateProject got %v want success", err)
		}
		filter := "filters_are_yet_to_be_implemented"
		// Get projects
		gotProjects, lastPage, err := s.ListProjects(filter, 2, "")
		if err != nil {
			t.Fatalf("ListProjects got %v want success", err)
		}
		if len(gotProjects) != 2 {
			t.Errorf("ListProjects got %v projects, want 2", len(gotProjects))
		}
		if p := gotProjects[0]; p.Name != name.FormatProject(pID1) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatProject(pID1))
		}
		if p := gotProjects[1]; p.Name != name.FormatProject(pID2) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatProject(pID2))
		}
		// Get projects again
		gotProjects, _, err = s.ListProjects(filter, 100, lastPage)
		if err != nil {
			t.Fatalf("ListProjects got %v want success", err)
		}
		if len(gotProjects) != 1 {
			t.Errorf("ListProjects got %v projects, want 1", len(gotProjects))
		}
		if p := gotProjects[0]; p.Name != name.FormatProject(pID3) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatProject(pID3))
		}
	})

	t.Run("NotesPagination", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "project"
		nID1 := "note1"
		op1 := testutil.Note(pID)
		op1.Name = name.FormatNote(pID, nID1)
		if err := s.CreateNote(op1); err != nil {
			t.Errorf("CreateNote got %v want success", err)
		}
		nID2 := "note2"
		op2 := testutil.Note(pID)
		op2.Name = name.FormatNote(pID, nID2)
		if err := s.CreateNote(op2); err != nil {
			t.Errorf("CreateNote got %v want success", err)
		}
		nID3 := "note3"
		op3 := testutil.Note(pID)
		op3.Name = name.FormatNote(pID, nID3)
		if err := s.CreateNote(op3); err != nil {
			t.Errorf("CreateNote got %v want success", err)
		}
		filter := "filters_are_yet_to_be_implemented"
		// Get occurrences
		gotNotes, lastPage, err := s.ListNotes(pID, filter, 2, "")
		if err != nil {
			t.Fatalf("ListNotes got %v want success", err)
		}
		if len(gotNotes) != 2 {
			t.Errorf("ListNotes got %v notes, want 2", len(gotNotes))
		}
		if p := gotNotes[0]; p.Name != name.FormatNote(pID, nID1) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatNote(pID, nID1))
		}
		if p := gotNotes[1]; p.Name != name.FormatNote(pID, nID2) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatNote(pID, nID2))
		}
		// Get occurrences again
		gotNotes, _, err = s.ListNotes(pID, filter, 100, lastPage)
		if err != nil {
			t.Fatalf("ListNotes got %v want success", err)
		}
		if len(gotNotes) != 1 {
			t.Errorf("ListNotes got %v notes, want 1", len(gotNotes))
		}
		if p := gotNotes[0]; p.Name != name.FormatNote(pID, nID3) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatNote(pID, nID3))
		}
	})

	t.Run("OccurrencePagination", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "project"
		nPID := "noteproject"
		oID1 := "occurrence1"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		op1 := testutil.Occurrence(pID, n.Name)
		op1.Name = name.FormatOccurrence(pID, oID1)
		if err := s.CreateOccurrence(op1); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		oID2 := "occurrence2"
		op2 := testutil.Occurrence(pID, n.Name)
		op2.Name = name.FormatOccurrence(pID, oID2)
		if err := s.CreateOccurrence(op2); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		oID3 := "occurrence3"
		op3 := testutil.Occurrence(pID, n.Name)
		op3.Name = name.FormatOccurrence(pID, oID3)
		if err := s.CreateOccurrence(op3); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		filter := "filters_are_yet_to_be_implemented"
		// Get occurrences
		gotOccurrences, lastPage, err := s.ListOccurrences(pID, filter, 2, "")
		if err != nil {
			t.Fatalf("ListOccurrences got %v want success", err)
		}
		if len(gotOccurrences) != 2 {
			t.Errorf("ListOccurrences got %v occurrences, want 2", len(gotOccurrences))
		}
		if p := gotOccurrences[0]; p.Name != name.FormatOccurrence(pID, oID1) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID1))
		}
		if p := gotOccurrences[1]; p.Name != name.FormatOccurrence(pID, oID2) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID2))
		}
		// Get occurrences again
		gotOccurrences, _, err = s.ListOccurrences(pID, filter, 100, lastPage)
		if err != nil {
			t.Fatalf("ListOccurrences got %v want success", err)
		}
		if len(gotOccurrences) != 1 {
			t.Errorf("ListOccurrences got %v operations, want 1", len(gotOccurrences))
		}
		if p := gotOccurrences[0]; p.Name != name.FormatOccurrence(pID, oID3) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID3))
		}
	})

	t.Run("NoteOccurrencePagination", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "project"
		nPID := "noteproject"
		oID1 := "occurrence1"
		n := testutil.Note(nPID)
		if err := s.CreateNote(n); err != nil {
			t.Fatalf("CreateNote got %v want success", err)
		}
		op1 := testutil.Occurrence(pID, n.Name)
		op1.Name = name.FormatOccurrence(pID, oID1)
		if err := s.CreateOccurrence(op1); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		oID2 := "occurrence2"
		op2 := testutil.Occurrence(pID, n.Name)
		op2.Name = name.FormatOccurrence(pID, oID2)
		if err := s.CreateOccurrence(op2); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		oID3 := "occurrence3"
		op3 := testutil.Occurrence(pID, n.Name)
		op3.Name = name.FormatOccurrence(pID, oID3)
		if err := s.CreateOccurrence(op3); err != nil {
			t.Errorf("CreateOccurrence got %v want success", err)
		}
		filter := "filters_are_yet_to_be_implemented"
		_, nID, err := name.ParseNote(n.Name)
		// Get occurrences
		gotOccurrences, lastPage, err := s.ListNoteOccurrences(nPID, nID, filter, 2, "")
		if err != nil {
			t.Fatalf("ListNoteOccurrences got %v want success", err)
		}
		if len(gotOccurrences) != 2 {
			t.Errorf("ListNoteOccurrences got %v occurrences, want 2", len(gotOccurrences))
		}
		if p := gotOccurrences[0]; p.Name != name.FormatOccurrence(pID, oID1) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID1))
		}
		if p := gotOccurrences[1]; p.Name != name.FormatOccurrence(pID, oID2) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID2))
		}
		// Get occurrences again
		gotOccurrences, _, err = s.ListNoteOccurrences(nPID, nID, filter, 100, lastPage)
		if err != nil {
			t.Fatalf("ListNoteOccurrences got %v want success", err)
		}
		if len(gotOccurrences) != 1 {
			t.Errorf("ListNoteOccurrences got %v operations, want 1", len(gotOccurrences))
		}
		if p := gotOccurrences[0]; p.Name != name.FormatOccurrence(pID, oID3) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOccurrence(pID, oID3))
		}
	})

	t.Run("OperationPagination", func(t *testing.T) {
		s, cleanUp := createStore(t)
		defer cleanUp()
		pID := "project1"
		oID1 := "operation1"
		op1 := testutil.Operation(pID)
		op1.Name = name.FormatOperation(pID, oID1)
		if err := s.CreateOperation(op1); err != nil {
			t.Errorf("CreateOperation got %v want success", err)
		}
		oID2 := "operation2"
		op2 := testutil.Operation(pID)
		op2.Name = name.FormatOperation(pID, oID2)
		if err := s.CreateOperation(op2); err != nil {
			t.Errorf("CreateOperation got %v want success", err)
		}
		oID3 := "operation3"
		op3 := testutil.Operation(pID)
		op3.Name = name.FormatOperation(pID, oID3)
		if err := s.CreateOperation(op3); err != nil {
			t.Errorf("CreateOperation got %v want success", err)
		}
		filter := "filters_are_yet_to_be_implemented"
		// Get operations
		gotOperations, lastPage, err := s.ListOperations(pID, filter, 2, "")
		if err != nil {
			t.Fatalf("ListOperations got %v want success", err)
		}
		if len(gotOperations) != 2 {
			t.Errorf("ListOperations got %v operations, want 2", len(gotOperations))
		}
		if p := gotOperations[0]; p.Name != name.FormatOperation(pID, oID1) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOperation(pID, oID1))
		}
		if p := gotOperations[1]; p.Name != name.FormatOperation(pID, oID2) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOperation(pID, oID2))
		}
		// Get operations again
		gotOperations, _, err = s.ListOperations(pID, filter, 100, lastPage)
		if err != nil {
			t.Fatalf("ListOperations got %v want success", err)
		}
		if len(gotOperations) != 1 {
			t.Errorf("ListOperations got %v operations, want 1", len(gotOperations))
		}
		if p := gotOperations[0]; p.Name != name.FormatOperation(pID, oID3) {
			t.Fatalf("Got %s want %s", p.Name, name.FormatOperation(pID, oID3))
		}
	})
}
