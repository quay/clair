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

package v1alpha1

import (
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/net/context"

	"github.com/grafeas/grafeas/samples/server/go-server/api/server/name"
	"github.com/grafeas/grafeas/samples/server/go-server/api/server/storage"
	"github.com/grafeas/grafeas/samples/server/go-server/api/server/testing"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	opspb "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createProject(t *testing.T, pID string, ctx context.Context, g Grafeas) {
	req := pb.CreateProjectRequest{Project: &pb.Project{Name: name.FormatProject(pID)}}
	if _, err := g.CreateProject(ctx, &req); err != nil {
		t.Errorf("CreateProject(empty operation): got %v, want success", err)
	}
}

func TestCreateProject(t *testing.T) {
	ctx := context.Background()
	pID := "myproject"
	g := Grafeas{storage.NewMemStore()}
	req := pb.CreateProjectRequest{Project: &pb.Project{Name: name.FormatProject(pID)}}
	_, err := g.CreateProject(ctx, &req)
	if err != nil {
		t.Errorf("CreateProject(empty operation): got %v, want success", err)
	}
	_, err = g.CreateProject(ctx, &req)
	if s, _ := status.FromError(err); s.Code() != codes.AlreadyExists {
		t.Errorf("CreateProject(empty operation): got %v, want AlreadyExists", err)
	}
}

func TestCreateOperation(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	op := &opspb.Operation{}
	req := pb.CreateOperationRequest{Parent: "projects/opp", Operation: op}
	if _, err := g.CreateOperation(ctx, &req); err == nil {
		t.Error("CreateOperation(empty operation): got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.InvalidArgument {
		t.Errorf("CreateOperation(empty operation): got %v, want InvalidArgument", err)
	}
	pID := "vulnerability-scanner-a"
	op = testutil.Operation(pID)
	parent := name.FormatProject(pID)
	req = pb.CreateOperationRequest{Parent: parent, Operation: op}
	if _, err := g.CreateOperation(ctx, &req); err == nil {
		t.Error("CreateOperation: got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.NotFound {
		t.Errorf("CreateOperation: got %v, want NotFound)", err)
	}
	createProject(t, pID, ctx, g)
	if _, err := g.CreateOperation(ctx, &req); error(err) != nil {
		t.Errorf("CreateOperation(%v) got %#v, want success", op, err)
	}
}

func TestCreateOccurrence(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	parent := name.FormatProject(pID)
	createProject(t, pID, ctx, g)
	req := &pb.CreateNoteRequest{Parent: parent, Note: n}
	if _, err := g.CreateNote(ctx, req); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", req, err)
	}
	oReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: &pb.Occurrence{}}
	if _, err := g.CreateOccurrence(ctx, oReq); err == nil {
		t.Error("CreateOccurrence(empty occ): got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.InvalidArgument {
		t.Errorf("CreateOccurrence(empty occ): got %v, want InvalidArgument)", err)
	}
	pID = "occurrence-project"
	o := testutil.Occurrence(pID, n.Name)
	parent = name.FormatProject(pID)
	oReq = &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
	// Try to insert an occurrence without first creating its project, expect failure
	if _, err := g.CreateOccurrence(ctx, oReq); err == nil {
		t.Error("CreateOccurrence: got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.NotFound {
		t.Errorf("CreateOccurrence: got %v, want NotFound)", err)
	}
	createProject(t, pID, ctx, g)
	if _, err := g.CreateOccurrence(ctx, oReq); err != nil {
		t.Errorf("CreateOccurrence(%v) got %v, want success", oReq, err)
	}
	// Try to insert an occurrence for a note that does not exist.
	o.Name = "projects/testproject/occurrences/nonote"
	o.NoteName = "projects/scan-provider/notes/notthere"
	oReq = &pb.CreateOccurrenceRequest{Parent: "projects/testproject", Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, oReq); err == nil {
		t.Errorf("CreateOccurrence got success, want Error")
	} else if s, _ := status.FromError(err); s.Code() != codes.NotFound {
		t.Errorf("CreateOccurrence got code %v want %v", err, codes.NotFound)
	}
}

func TestCreateNote(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	n := &pb.Note{}
	req := &pb.CreateNoteRequest{Parent: "projects/foo", Note: n}
	// Try to insert an empty note, expect failure
	if _, err := g.CreateNote(ctx, req); err == nil {
		t.Error("CreateNote(empty note): got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.InvalidArgument {
		t.Errorf("CreateNote(empty note): got %v, want %v", err, codes.InvalidArgument)
	}
	// Try to insert an onccurrence without first creating its project, expect failure
	pID := "vulnerability-scanner-a"
	n = testutil.Note(pID)
	parent := name.FormatProject(pID)
	req = &pb.CreateNoteRequest{Parent: parent, Note: n}
	if _, err := g.CreateNote(ctx, req); err == nil {
		t.Error("CreateNote: got success, want error")
	} else if s, _ := status.FromError(err); s.Code() != codes.NotFound {
		t.Errorf("CreateNote: got %v, want NotFound)", err)
	}
	createProject(t, pID, ctx, g)
	if _, err := g.CreateNote(ctx, req); err != nil {
		t.Errorf("CreateNote(%v) got %v, want success", n, err)
	}
}

func TestCreateNoteOccurrenceWithOperation(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	o := testutil.Operation(pID)
	createProject(t, pID, ctx, g)
	parent := name.FormatProject(pID)
	cReq := &pb.CreateOperationRequest{Parent: parent, Operation: o}
	if _, err := g.CreateOperation(ctx, cReq); err != nil {
		t.Fatalf("CreateOperation(%v) got %v, want success", o, err)
	}
	n := testutil.Note(pID)
	n.OperationName = "projects/vulnerability-scanner-a/operation/junk"
	nreq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	// Try to create a Note with operation that does not exist and expect failure
	if _, err := g.CreateNote(ctx, nreq); err == nil {
		t.Errorf("TestCreateNoteWithOperation: got %v, want %v", err, codes.NotFound)
	}
	n.OperationName = o.Name
	nreq = &pb.CreateNoteRequest{Parent: parent, Note: n}
	// Try to create a Note with operation that we just created and expect success
	if _, err := g.CreateNote(ctx, nreq); err != nil {
		t.Errorf("TestCreateNoteWithOperation(%v) got %v, want success", n.OperationName, err)
	}
	// Try to create occurrence with operation name
	occ := testutil.Occurrence(pID, n.Name)
	occ.OperationName = "projects/vulnerability-scanner-a/operation/junk"
	parent = name.FormatProject(pID)
	occReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: occ}
	// Try to create an Occurrence with operation that does not exist and expect failure
	if _, err := g.CreateOccurrence(ctx, occReq); err == nil {
		t.Errorf("TestCreateNoteWithOperation: got %v, want %v", err, codes.NotFound)
	}
	occ.OperationName = o.Name
	occReq = &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: occ}
	// Try to create an Occurrence with operation that we just created and expect success
	if _, err := g.CreateOccurrence(ctx, occReq); err != nil {
		t.Errorf("TestCreateNoteWithOperation(%v) got %v, want success", occ.OperationName, err)

	}
}

func TestDeleteProject(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "myproject"
	req := pb.DeleteProjectRequest{Name: name.FormatProject(pID)}
	if _, err := g.DeleteProject(ctx, &req); err == nil {
		t.Error("DeleteProject: got success, want error")
	}
	createProject(t, pID, ctx, g)
	if _, err := g.DeleteProject(ctx, &req); err != nil {
		t.Errorf("CreateProject(empty operation): got %v, want success", err)
	}
}

func TestDeleteNote(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	req := &pb.DeleteNoteRequest{Name: n.Name}
	if _, err := g.DeleteNote(ctx, req); err == nil {
		t.Error("DeleteNote that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Errorf("CreateNote(%v) got %v, want success", n, err)
	}
	if _, err := g.DeleteNote(ctx, req); err != nil {
		t.Errorf("DeleteNote  got %v, want success", err)
	}
}

func TestDeleteOccurrence(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	// CreateNote so we can create an occurrence
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	pID = "occurrence-project"
	o := testutil.Occurrence(pID, n.Name)
	createProject(t, pID, ctx, g)

	parent = name.FormatProject(pID)
	oReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, oReq); err != nil {
		t.Fatalf("CreateOccurrence(%v) got %v, want success", n, err)
	}
	dReq := &pb.DeleteOccurrenceRequest{Name: o.Name}
	if _, err := g.DeleteOccurrence(ctx, dReq); err != nil {
		t.Errorf("DeleteOccurrence  got %v, want success", err)
	}
}

func TestDeleteOperation(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	o := testutil.Operation(pID)
	createProject(t, pID, ctx, g)
	req := &opspb.DeleteOperationRequest{Name: o.Name}
	if _, err := g.DeleteOperation(ctx, req); err == nil {
		t.Error("DeleteOperation that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateOperationRequest{Parent: parent, Operation: o}
	if _, err := g.CreateOperation(ctx, cReq); err != nil {
		t.Fatalf("CreateOperation(%v) got %v, want success", o, err)
	}
	if _, err := g.DeleteOperation(ctx, req); err != nil {
		t.Errorf("DeleteOperation  got %v, want success", err)
	}
}

func TestGetProjects(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "myproject"
	req := pb.GetProjectRequest{Name: name.FormatProject(pID)}
	if _, err := g.GetProject(ctx, &req); err == nil {
		t.Error("GetProject that doesn't exist got success, want err")
	}
	createProject(t, pID, ctx, g)
	if _, err := g.GetProject(ctx, &req); err != nil {
		t.Errorf("GetProject: got %v, want success", err)
	}
}

func TestGetNote(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	req := &pb.GetNoteRequest{Name: n.Name}
	if _, err := g.GetNote(ctx, req); err == nil {
		t.Error("GetNote that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	if got, err := g.GetNote(ctx, req); err != nil {
		t.Fatalf("GetNote(%v) got %v, want success", n, err)
	} else if n.Name != got.Name || !reflect.DeepEqual(n.GetVulnerabilityType(), got.GetVulnerabilityType()) {
		t.Errorf("GetNote got %v, want %v", *got, n)
	}
}

func TestGetOccurrence(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	opID := "occurrence-project"
	o := testutil.Occurrence(opID, n.Name)
	createProject(t, opID, ctx, g)
	req := &pb.GetOccurrenceRequest{Name: o.Name}
	if _, err := g.GetOccurrence(ctx, req); err == nil {
		t.Error("GetOccurrence that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	oParent := name.FormatProject(opID)
	ocReq := &pb.CreateOccurrenceRequest{Parent: oParent, Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, ocReq); err != nil {
		t.Fatalf("CreateOccurrence(%v) got %v, want success", n, err)
	}
	if got, err := g.GetOccurrence(ctx, req); err != nil {
		t.Fatalf("GetOccurrence(%v) got %v, want success", o, err)
	} else if o.Name != got.Name || !reflect.DeepEqual(o.GetVulnerabilityDetails(), got.GetVulnerabilityDetails()) {
		t.Errorf("GetOccurrence got %v, want %v", *got, o)
	}
}

func TestGetOperation(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	o := testutil.Operation(pID)
	createProject(t, pID, ctx, g)
	req := &opspb.GetOperationRequest{Name: o.Name}
	if _, err := g.GetOperation(ctx, req); err == nil {
		t.Error("GetOperation that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateOperationRequest{Parent: parent, Operation: o}
	if _, err := g.CreateOperation(ctx, cReq); err != nil {
		t.Fatalf("CreateOperation(%v) got %v, want success", o, err)
	}
	if got, err := g.GetOperation(ctx, req); err != nil {
		t.Fatalf("GetOperation(%v) got %v, want success", o, err)
	} else if o.Name != got.Name || !reflect.DeepEqual(got, o) {
		t.Errorf("GetOperation got %v, want %v", *got, o)
	}
}

func TestGetOccurrenceNote(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	opID := "occurrence-project"
	o := testutil.Occurrence(opID, n.Name)
	createProject(t, opID, ctx, g)

	req := &pb.GetOccurrenceNoteRequest{Name: o.Name}
	if _, err := g.GetOccurrenceNote(ctx, req); err == nil {
		t.Error("GetOccurrenceNote that doesn't exist got success, want err")
	}
	pID, _, err := name.ParseNote(n.Name)
	if err != nil {
		t.Fatalf("Error parsing occurrence name %v", err)
	}
	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}

	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	parent = name.FormatProject(opID)
	coReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, coReq); err != nil {
		t.Fatalf("CreateOccurrence(%v) got %v, want success", n, err)
	}
	if got, err := g.GetOccurrenceNote(ctx, req); err != nil {
		t.Fatalf("GetOccurrenceNote(%v) got %v, want success", n, err)
	} else if n.Name != got.Name || !reflect.DeepEqual(n.GetVulnerabilityType(), got.GetVulnerabilityType()) {
		t.Errorf("GetOccurrenceNote got %v, want %v", *got, n)
	}
}

func TestUpdateNote(t *testing.T) {
	ctx := context.Background()
	// Update Note that doesn't exist
	updateDesc := "this is a new description"
	g := Grafeas{storage.NewMemStore()}
	pID := "vulnerability-scanner-a"
	n := testutil.Note(pID)
	createProject(t, pID, ctx, g)
	update := testutil.Note(pID)
	update.LongDescription = updateDesc
	req := &pb.UpdateNoteRequest{Name: n.Name, Note: n}
	if _, err := g.UpdateNote(ctx, req); err != nil {
		t.Error("UpdateNote that doesn't exist got success, want err")
	}

	parent := name.FormatProject(pID)
	cReq := &pb.CreateNoteRequest{Parent: parent, Note: n}
	// Actually create note
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}

	// Update Note name and fail
	update.Name = "New name"
	req = &pb.UpdateNoteRequest{Name: n.Name, Note: update}
	if _, err := g.UpdateNote(ctx, req); err == nil {
		t.Error("UpdateNote that with name change got success, want err")
	}

	// Update Note and verify that update worked.
	update = testutil.Note(pID)
	update.LongDescription = updateDesc
	req = &pb.UpdateNoteRequest{Name: n.Name, Note: update}
	if got, err := g.UpdateNote(ctx, req); err != nil {
		t.Errorf("UpdateNote got %v, want success", err)
	} else if updateDesc != update.LongDescription {
		t.Errorf("UpdateNote got %v, want %v",
			got.LongDescription, updateDesc)
	}
	if got, err := g.GetNote(ctx, &pb.GetNoteRequest{Name: n.Name}); err != nil {
		t.Fatalf("GetNote(%v) got %v, want success", n, err)
	} else if updateDesc != got.LongDescription {
		t.Errorf("GetNote got %v, want %v", got.LongDescription, updateDesc)
	}
}

func TestUpdateOccurrence(t *testing.T) {
	ctx := context.Background()
	// Update occurrence that doesn't exist
	g := Grafeas{storage.NewMemStore()}
	npID := "vulnerability-scanner-a"
	n := testutil.Note(npID)
	createProject(t, npID, ctx, g)
	nParent := name.FormatProject(npID)
	cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}

	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	pID := "occurrence-project"
	o := testutil.Occurrence(pID, n.Name)
	createProject(t, pID, ctx, g)

	req := &pb.UpdateOccurrenceRequest{Name: o.Name, Occurrence: o}
	if _, err := g.UpdateOccurrence(ctx, req); err == nil {
		t.Error("UpdateOccurrence that doesn't exist got success, want err")
	}
	parent := name.FormatProject(pID)
	ocReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, ocReq); err != nil {
		t.Fatalf("CreateOccurrence(%v) got %v, want success", n, err)
	}
	// update occurrence name
	update := testutil.Occurrence(pID, n.Name)
	update.Name = "New name"
	req = &pb.UpdateOccurrenceRequest{Name: update.Name, Occurrence: update}
	if _, err := g.UpdateOccurrence(ctx, req); err == nil {
		t.Error("UpdateOccurrence with name change got success, want err")
	}

	// update note name to a note that doesn't exist
	update = testutil.Occurrence(pID, "projects/p/notes/bar")
	req = &pb.UpdateOccurrenceRequest{Name: o.Name, Occurrence: update}
	if _, err := g.UpdateOccurrence(ctx, req); err == nil {
		t.Error("UpdateOccurrence that with note name that doesn't exist" +
			" got success, want err")
	}

	// update note name to a note that does exist
	n = testutil.Note(npID)
	newName := fmt.Sprintf("%v-new", n.Name)
	n.Name = newName

	cReq = &pb.CreateNoteRequest{Parent: nParent, Note: n}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	update = testutil.Occurrence(pID, n.Name)
	req = &pb.UpdateOccurrenceRequest{Name: o.Name, Occurrence: update}
	if got, err := g.UpdateOccurrence(ctx, req); err != nil {
		t.Errorf("UpdateOccurrence got %v, want success", err)
	} else if n.Name != got.NoteName {
		t.Errorf("UpdateOccurrence got %v, want %v",
			got.NoteName, n.Name)
	}
	gReq := &pb.GetOccurrenceRequest{Name: o.Name}
	if got, err := g.GetOccurrence(ctx, gReq); err != nil {
		t.Fatalf("GetOccurrence(%v) got %v, want success", n, err)
	} else if n.Name != got.NoteName {
		t.Errorf("GetOccurrence got %v, want %v",
			got.NoteName, n.Name)
	}
}

func TestListOccurrences(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	npID := "vulnerability-scanner-a"
	n := testutil.Note(npID)
	nParent := name.FormatProject(npID)
	cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}
	createProject(t, npID, ctx, g)

	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	os := []*pb.Occurrence{}
	findProject := "findThese"
	createProject(t, findProject, ctx, g)
	dontFind := "dontFind"
	createProject(t, dontFind, ctx, g)
	for i := 0; i < 20; i++ {
		pID := "_"
		o := testutil.Occurrence(pID, n.Name)
		if i < 5 {
			o.Name = name.FormatOccurrence(findProject, string(i))
		} else {
			o.Name = name.FormatOccurrence(dontFind, string(i))
		}
		parent := name.FormatProject(pID)
		ocReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
		if _, err := g.CreateOccurrence(ctx, ocReq); err != nil {
			t.Fatalf("CreateOccurrence got %v want success", err)
		}
		os = append(os, o)
	}

	lReq := &pb.ListOccurrencesRequest{
		Parent:   name.FormatProject(findProject),
		PageSize: 100,
	}
	resp, lErr := g.ListOccurrences(ctx, lReq)
	if lErr != nil {
		t.Fatalf("ListOccurrences got %v want success", lErr)
	}
	if len(resp.Occurrences) != 5 {
		t.Errorf("resp.Occurrences got %d, want 5", len(resp.Occurrences))
	}
}

func TestListProjects(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	var projects []string
	for i := 0; i < 20; i++ {
		pID := fmt.Sprintf("proj%v", i)
		req := pb.CreateProjectRequest{Project: &pb.Project{Name: name.FormatProject(pID)}}
		if _, err := g.CreateProject(ctx, &req); err != nil {
			t.Errorf("CreateProject: got %v, want success", err)
		}
		if _, err := g.CreateProject(ctx, &req); err == nil {
			t.Errorf("CreateProject: got %v, want InvalidArgument", err)
		}
		projects = append(projects, name.FormatProject(pID))
	}
	req := pb.ListProjectsRequest{}
	_, err := g.ListProjects(ctx, &req)
	if err != nil {
		t.Errorf("ListProjects: got %v, want success", err)
	}
}

func TestListOperations(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	findProject := "findThese"
	createProject(t, findProject, ctx, g)
	dontFind := "dontFind"
	createProject(t, dontFind, ctx, g)
	for i := 0; i < 20; i++ {
		pID := "vulnerability-scanner-a"
		o := testutil.Operation(pID)
		if i < 5 {
			o.Name = name.FormatOperation(findProject, string(i))
		} else {
			o.Name = name.FormatOperation(dontFind, string(i))
		}
		parent := name.FormatProject(pID)
		cReq := &pb.CreateOperationRequest{Parent: parent, Operation: o}
		if _, err := g.CreateOperation(ctx, cReq); err != nil {
			t.Fatalf("CreateOperation(%v) got %v, want success", o, err)
		}
	}

	lReq := &opspb.ListOperationsRequest{Name: name.FormatProject(findProject)}
	resp, err := g.ListOperations(ctx, lReq)
	if err != nil {
		t.Fatalf("ListOperations got %v want success", err)
	}
	if len(resp.Operations) != 5 {
		t.Errorf("resp.Operations got %d, want 5", len(resp.Operations))
	}
}

func TestListNotes(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	findProject := "findThese"
	createProject(t, findProject, ctx, g)
	dontFind := "dontFind"
	createProject(t, dontFind, ctx, g)
	for i := 0; i < 20; i++ {
		npID := "vulnerability-scanner-a"
		n := testutil.Note(npID)
		if i < 5 {
			n.Name = name.FormatNote(findProject, string(i))
		} else {
			n.Name = name.FormatNote(dontFind, string(i))
		}
		nParent := name.FormatProject(npID)
		cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}
		if _, err := g.CreateNote(ctx, cReq); err != nil {
			t.Fatalf("CreateNote(%v) got %v, want success", n, err)
		}
	}

	req := &pb.ListNotesRequest{Parent: name.FormatProject(findProject)}
	resp, err := g.ListNotes(ctx, req)
	if err != nil {
		t.Fatalf("ListNotes got %v want success", err)
	}
	if len(resp.Notes) != 5 {
		t.Errorf("resp.Notes got %d, want 5", len(resp.Notes))
	}
}

func TestListNoteOccurrences(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	npID := "vulnerability-scanner-a"
	n := testutil.Note(npID)
	createProject(t, npID, ctx, g)
	nParent := name.FormatProject(npID)
	cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	findProject := "findThese"
	createProject(t, findProject, ctx, g)
	dontFind := "dontFind"
	createProject(t, dontFind, ctx, g)
	for i := 0; i < 20; i++ {
		pID := "_"
		o := testutil.Occurrence(pID, n.Name)
		if i < 5 {
			o.Name = name.FormatOccurrence(findProject, string(i))
		} else {
			o.Name = name.FormatOccurrence(dontFind, string(i))
		}
		parent := name.FormatProject(pID)
		ocReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
		if _, err := g.CreateOccurrence(ctx, ocReq); err != nil {
			t.Fatalf("CreateOccurrence got %v want success", err)
		}
	}
	// Create an occurrence tied to another note, to make sure we don't find it.
	otherN := testutil.Note("")
	otherN.Name = "projects/np/notes/not-to-find"
	npID, _, err := name.ParseNote(otherN.Name)
	if err != nil {
		t.Fatalf("Error parsing note name %v", err)
	}
	nParent = name.FormatProject(npID)
	createProject(t, npID, ctx, g)
	cReq = &pb.CreateNoteRequest{Parent: nParent, Note: otherN}
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote got %v want success", err)
	}
	pID := "occurrence-project"
	o := testutil.Occurrence(pID, otherN.Name)
	createProject(t, pID, ctx, g)
	parent := name.FormatProject(pID)
	ocReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
	if _, err := g.CreateOccurrence(ctx, ocReq); err != nil {
		t.Fatalf("CreateOccurrence got %v want success", err)
	}
	pID, _, err = name.ParseNote(n.Name)
	if err != nil {
		t.Fatalf("Error parsing note name %v", err)
	}
	lReq := &pb.ListNoteOccurrencesRequest{Name: n.Name}
	resp, lErr := g.ListNoteOccurrences(ctx, lReq)
	if lErr != nil {
		t.Fatalf("ListNoteOccurrences got %v want success", err)
	}
	if len(resp.Occurrences) != 20 {
		t.Errorf("resp.Occurrences got %d, want 20", len(resp.Occurrences))
	}
}

func TestProjectsPagination(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	var projects []string
	for i := 0; i < 20; i++ {
		pID := fmt.Sprintf("proj%v", i)
		req := pb.CreateProjectRequest{Project: &pb.Project{Name: name.FormatProject(pID)}}
		if _, err := g.CreateProject(ctx, &req); err != nil {
			t.Errorf("CreateProject: got %v, want success", err)
		}
		projects = append(projects, name.FormatProject(pID))
	}
	req := pb.ListProjectsRequest{
		PageSize: 15,
	}
	resp, err := g.ListProjects(ctx, &req)
	if err != nil {
		t.Errorf("ListProjects: got %v, want success", err)
	}
	if 15 != len(resp.Projects) {
		t.Errorf("ListProjects: expected 15 projects, got %d", len(resp.Projects))
	}
	req = pb.ListProjectsRequest{
		PageSize:  15,
		PageToken: resp.NextPageToken,
	}
	resp, err = g.ListProjects(ctx, &req)
	if err != nil {
		t.Errorf("ListProjects: got %v, want success", err)
	}
	if 5 != len(resp.Projects) {
		t.Errorf("ListProjects: expected 5 projects, got %d", len(resp.Projects))
	}
}

func TestNotePagination(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "myproject"
	createProject(t, pID, ctx, g)
	for i := 0; i < 20; i++ {
		o := testutil.Note(pID)
		o.Name = name.FormatNote(pID, string(i))
		parent := name.FormatProject(pID)
		cReq := &pb.CreateNoteRequest{Parent: parent, Note: o}
		if _, err := g.CreateNote(ctx, cReq); err != nil {
			t.Fatalf("CreateNote(%v) got %v, want success", o, err)
		}
	}
	req := pb.ListNotesRequest{
		Parent:   name.FormatProject(pID),
		PageSize: 15,
	}
	resp, err := g.ListNotes(ctx, &req)
	if err != nil {
		t.Errorf("ListNotes: got %v, want success", err)
	}
	if 15 != len(resp.Notes) {
		t.Errorf("ListNotes: expected 15 notes, got %d", len(resp.Notes))
	}
	req = pb.ListNotesRequest{
		Parent:    name.FormatProject(pID),
		PageSize:  15,
		PageToken: resp.NextPageToken,
	}
	resp, err = g.ListNotes(ctx, &req)
	if err != nil {
		t.Errorf("ListNotes: got %v, want success", err)
	}
	if 5 != len(resp.Notes) {
		t.Errorf("ListNotes: expected 5 notes, got %d", len(resp.Notes))
	}
}

func TestOccurrencePagination(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	npID := "vulnerability-scanner-a"
	n := testutil.Note(npID)
	nParent := name.FormatProject(npID)
	cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}
	createProject(t, npID, ctx, g)
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	pID := "myproject"
	createProject(t, pID, ctx, g)
	for i := 0; i < 20; i++ {
		o := testutil.Occurrence(pID, n.Name)
		o.Name = name.FormatOccurrence(pID, string(i))
		parent := name.FormatProject(pID)
		cReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
		if _, err := g.CreateOccurrence(ctx, cReq); err != nil {
			t.Fatalf("CreateOccurrence(%v) got %v, want success", o, err)
		}
	}
	req := pb.ListOccurrencesRequest{
		Parent:   name.FormatProject(pID),
		PageSize: 15,
	}
	resp, err := g.ListOccurrences(ctx, &req)
	if err != nil {
		t.Errorf("ListOccurrences: got %v, want success", err)
	}
	if 15 != len(resp.Occurrences) {
		t.Errorf("ListOccurrences: expected 15 occurrences, got %d", len(resp.Occurrences))
	}
	req = pb.ListOccurrencesRequest{
		Parent:    name.FormatProject(pID),
		PageSize:  15,
		PageToken: resp.NextPageToken,
	}
	resp, err = g.ListOccurrences(ctx, &req)
	if err != nil {
		t.Errorf("ListOccurrences: got %v, want success", err)
	}
	if 5 != len(resp.Occurrences) {
		t.Errorf("ListOccurrences: expected 5 occurrences, got %d", len(resp.Occurrences))
	}
}

func TestNoteOccurrencePagination(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	npID := "vulnerability-scanner-a"
	n := testutil.Note(npID)
	nParent := name.FormatProject(npID)
	cReq := &pb.CreateNoteRequest{Parent: nParent, Note: n}
	createProject(t, npID, ctx, g)
	if _, err := g.CreateNote(ctx, cReq); err != nil {
		t.Fatalf("CreateNote(%v) got %v, want success", n, err)
	}
	pID := "myproject"
	createProject(t, pID, ctx, g)
	for i := 0; i < 20; i++ {
		o := testutil.Occurrence(pID, n.Name)
		o.Name = name.FormatOccurrence(pID, string(i))
		parent := name.FormatProject(pID)
		cReq := &pb.CreateOccurrenceRequest{Parent: parent, Occurrence: o}
		if _, err := g.CreateOccurrence(ctx, cReq); err != nil {
			t.Fatalf("CreateOccurrence(%v) got %v, want success", o, err)
		}
	}
	req := pb.ListNoteOccurrencesRequest{
		Name:     n.Name,
		PageSize: 15,
	}
	resp, err := g.ListNoteOccurrences(ctx, &req)
	if err != nil {
		t.Errorf("ListNoteOccurrences: got %v, want success", err)
	}
	if 15 != len(resp.Occurrences) {
		t.Errorf("ListNoteOccurrences: expected 15 occurrences, got %d", len(resp.Occurrences))
	}
	req = pb.ListNoteOccurrencesRequest{
		Name:      n.Name,
		PageSize:  15,
		PageToken: resp.NextPageToken,
	}
	resp, err = g.ListNoteOccurrences(ctx, &req)
	if err != nil {
		t.Errorf("ListNoteOccurrences: got %v, want success", err)
	}
	if 5 != len(resp.Occurrences) {
		t.Errorf("ListNoteOccurrences: expected 5 occurrences, got %d", len(resp.Occurrences))
	}
}

func TestOperationPagination(t *testing.T) {
	ctx := context.Background()
	g := Grafeas{storage.NewMemStore()}
	pID := "myproject"
	createProject(t, pID, ctx, g)
	for i := 0; i < 20; i++ {
		o := testutil.Operation(pID)
		o.Name = name.FormatOperation(pID, string(i))
		parent := name.FormatProject(pID)
		cReq := &pb.CreateOperationRequest{Parent: parent, Operation: o}
		if _, err := g.CreateOperation(ctx, cReq); err != nil {
			t.Fatalf("CreateOperation(%v) got %v, want success", o, err)
		}
	}
	req := opspb.ListOperationsRequest{
		Name:     name.FormatProject(pID),
		PageSize: 15,
	}
	resp, err := g.ListOperations(ctx, &req)
	if err != nil {
		t.Errorf("ListOperations: got %v, want success", err)
	}
	if 15 != len(resp.Operations) {
		t.Errorf("ListOperations: expected 15 operations, got %d", len(resp.Operations))
	}
	req = opspb.ListOperationsRequest{
		Name:      name.FormatProject(pID),
		PageSize:  15,
		PageToken: resp.NextPageToken,
	}
	resp, err = g.ListOperations(ctx, &req)
	if err != nil {
		t.Errorf("ListOperations: got %v, want success", err)
	}
	if 5 != len(resp.Operations) {
		t.Errorf("ListOperations: expected 5 operations, got %d", len(resp.Operations))
	}
}
