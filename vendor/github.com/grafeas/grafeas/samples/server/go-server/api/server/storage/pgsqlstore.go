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
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/golang/protobuf/proto"
	"github.com/grafeas/grafeas/samples/server/go-server/api/server/name"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	"github.com/lib/pq"
	opspb "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pgSQLStore struct {
	*sql.DB
	paginationKey string
}

func NewPgSQLStore(config *PgSQLConfig) *pgSQLStore {
	err := createDatabase(createSourceString(config), config.DbName)
	if err != nil {
		log.Fatal(err.Error())
	}
	db, err := sql.Open("postgres", createSourceStringWithDbName(config))
	if err != nil {
		log.Fatal(err.Error())
	}
	if db.Ping() != nil {
		log.Fatal("Database server is not alive")
	}
	_, err = db.Exec(createTables)
	if err != nil {
		db.Close()
		log.Fatal(err.Error())
	}
	pg := pgSQLStore{
		DB:            db,
		paginationKey: config.PaginationKey,
	}
	return &pg
}

func createDatabase(source, dbName string) error {
	db, err := sql.Open("postgres", source)
	if err != nil {
		return err
	}
	defer db.Close()
	// Check if db exists
	res, err := db.Exec(
		fmt.Sprintf("SELECT * FROM pg_catalog.pg_database WHERE datname='%s'", dbName))
	if err != nil {
		return err
	}
	rowCnt, err := res.RowsAffected()
	if err != nil {
		return err
	}
	// Create database if it doesn't exist
	if rowCnt == 0 {
		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName))
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateProject adds the specified project to the store
func (pg *pgSQLStore) CreateProject(pID string) error {
	_, err := pg.DB.Exec(insertProject, name.FormatProject(pID))
	if err, ok := err.(*pq.Error); ok {
		// Check for unique_violation
		if err.Code == "23505" {
			return status.Error(codes.AlreadyExists, fmt.Sprintf("Project with name %q already exists", pID))
		} else {
			log.Println("Failed to insert Project in database", err)
			return status.Error(codes.Internal, "Failed to insert Project in database")
		}
	}
	return nil
}

// DeleteProject deletes the project with the given pID from the store
func (pg *pgSQLStore) DeleteProject(pID string) error {
	pName := name.FormatProject(pID)
	result, err := pg.DB.Exec(deleteProject, pName)
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Project from database")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Project from database")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Project with name %q does not Exist", pName))
	}
	return nil
}

// GetProject returns the project with the given pID from the store
func (pg *pgSQLStore) GetProject(pID string) (*pb.Project, error) {
	pName := name.FormatProject(pID)
	var exists bool
	err := pg.DB.QueryRow(projectExists, pName).Scan(&exists)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to query Project from database")
	}
	if !exists {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Project with name %q does not Exist", pName))
	}
	return &pb.Project{Name: pName}, nil
}

// ListProjects returns up to pageSize number of projects beginning at pageToken (or from
// start if pageToken is the emtpy string).
func (pg *pgSQLStore) ListProjects(filter string, pageSize int, pageToken string) ([]*pb.Project, string, error) {
	var rows *sql.Rows
	id := decryptInt64(pageToken, pg.paginationKey, 0)
	rows, err := pg.DB.Query(listProjects, pageSize, id)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to list Projects from database")
	}
	var projects []*pb.Project
	var lastId int64
	for rows.Next() {
		var name string
		err := rows.Scan(&lastId, &name)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to scan Project row")
		}
		projects = append(projects, &pb.Project{Name: name})
	}
	encryptedPage, err := encryptInt64(lastId, pg.paginationKey)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to paginate projects")
	}
	return projects, encryptedPage, nil
}

// CreateOccurrence adds the specified occurrence
func (pg *pgSQLStore) CreateOccurrence(o *pb.Occurrence) error {
	oPID, oID, err := name.ParseOccurrence(o.Name)
	if err != nil {
		log.Printf("Invalid occurrence name: %v", o.Name)
		return status.Error(codes.InvalidArgument, "Invalid occurrence name")
	}
	nPID, nID, err := name.ParseNote(o.NoteName)
	if err != nil {
		log.Printf("Invalid note name: %v", o.NoteName)
		return status.Error(codes.InvalidArgument, "Invalid note name")
	}
	_, err = pg.DB.Exec(insertOccurrence, oPID, oID, nPID, nID, proto.MarshalTextString(o))
	if err, ok := err.(*pq.Error); ok {
		// Check for unique_violation
		if err.Code == "23505" {
			return status.Error(codes.AlreadyExists, fmt.Sprintf("Occurrence with name %q already exists", o.Name))
		} else {
			log.Println("Failed to insert Occurrence in database", err)
			return status.Error(codes.Internal, "Failed to insert Occurrence in database")
		}
	}
	return nil
}

// DeleteOccurrence deletes the occurrence with the given pID and oID
func (pg *pgSQLStore) DeleteOccurrence(pID, oID string) error {
	result, err := pg.DB.Exec(deleteOccurrence, pID, oID)
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Occurrence from database")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Occurrence from database")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Occurrence with name %q/%q does not Exist", pID, oID))
	}
	return nil
}

// UpdateOccurrence updates the existing occurrence with the given projectID and occurrenceID
func (pg *pgSQLStore) UpdateOccurrence(pID, oID string, o *pb.Occurrence) error {
	result, err := pg.DB.Exec(updateOccurrence, pID, oID, proto.MarshalTextString(o))
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Occurrence")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Occurrence")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Occurrence with name %q/%q does not Exist", pID, oID))
	}
	return nil
}

// GetOccurrence returns the occurrence with pID and oID
func (pg *pgSQLStore) GetOccurrence(pID, oID string) (*pb.Occurrence, error) {
	var data string
	err := pg.DB.QueryRow(searchOccurrence, pID, oID).Scan(&data)
	switch {
	case err == sql.ErrNoRows:
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Occurrence with name %q/%q does not Exist", pID, oID))
	case err != nil:
		return nil, status.Error(codes.Internal, "Failed to query Occurrence from database")
	}
	var o pb.Occurrence
	proto.UnmarshalText(data, &o)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to unmarshal Occurrence from database")
	}
	return &o, nil
}

// ListOccurrences returns up to pageSize number of occurrences for this project (pID) beginning
// at pageToken (or from start if pageToken is the emtpy string).
func (pg *pgSQLStore) ListOccurrences(pID, filters string, pageSize int, pageToken string) ([]*pb.Occurrence, string, error) {
	var rows *sql.Rows
	id := decryptInt64(pageToken, pg.paginationKey, 0)
	rows, err := pg.DB.Query(listOccurrences, pID, pageSize, id)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to list Occurrences from database")
	}
	os := []*pb.Occurrence{}
	var lastId int64
	for rows.Next() {
		var data string
		err := rows.Scan(&lastId, &data)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to scan Occurrences row")
		}
		var o pb.Occurrence
		proto.UnmarshalText(data, &o)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to unmarshal Occurrence from database")
		}
		os = append(os, &o)
	}
	encryptedPage, err := encryptInt64(lastId, pg.paginationKey)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to paginate projects")
	}
	return os, encryptedPage, nil
}

// CreateNote adds the specified note
func (pg *pgSQLStore) CreateNote(n *pb.Note) error {
	pID, nID, err := name.ParseNote(n.Name)
	if err != nil {
		log.Printf("Invalid note name: %v", n.Name)
		return status.Error(codes.InvalidArgument, "Invalid note name")
	}
	_, err = pg.DB.Exec(insertNote, pID, nID, proto.MarshalTextString(n))
	if err, ok := err.(*pq.Error); ok {
		// Check for unique_violation
		if err.Code == "23505" {
			return status.Error(codes.AlreadyExists, fmt.Sprintf("Note with name %q already exists", n.Name))
		} else {
			log.Println("Failed to insert Note in database", err)
			return status.Error(codes.Internal, "Failed to insert Note in database")
		}
	}
	return nil
}

// DeleteNote deletes the note with the given pID and nID
func (pg *pgSQLStore) DeleteNote(pID, nID string) error {
	result, err := pg.DB.Exec(deleteNote, pID, nID)
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Note from database")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Note from database")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Note with name %q/%q does not Exist", pID, nID))
	}
	return nil
}

// UpdateNote updates the existing note with the given pID and nID
func (pg *pgSQLStore) UpdateNote(pID, nID string, n *pb.Note) error {
	result, err := pg.DB.Exec(updateNote, pID, nID, proto.MarshalTextString(n))
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Note")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Note")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Note with name %q/%q does not Exist", pID, nID))
	}
	return nil
}

// GetNote returns the note with project (pID) and note ID (nID)
func (pg *pgSQLStore) GetNote(pID, nID string) (*pb.Note, error) {
	var data string
	err := pg.DB.QueryRow(searchNote, pID, nID).Scan(&data)
	switch {
	case err == sql.ErrNoRows:
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Note with name %q/%q does not Exist", pID, nID))
	case err != nil:
		return nil, status.Error(codes.Internal, "Failed to query Note from database")
	}
	var note pb.Note
	proto.UnmarshalText(data, &note)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to unmarshal Note from database")
	}
	return &note, nil
}

// GetNoteByOccurrence returns the note attached to occurrence with pID and oID
func (pg *pgSQLStore) GetNoteByOccurrence(pID, oID string) (*pb.Note, error) {
	o, err := pg.GetOccurrence(pID, oID)
	if err != nil {
		return nil, err
	}
	nPID, nID, err := name.ParseNote(o.NoteName)
	if err != nil {
		log.Printf("Error parsing name: %v", o.NoteName)
		return nil, status.Error(codes.InvalidArgument, "Invalid Note name")
	}
	n, err := pg.GetNote(nPID, nID)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// ListNotes returns up to pageSize number of notes for this project (pID) beginning
// at pageToken (or from start if pageToken is the emtpy string).
func (pg *pgSQLStore) ListNotes(pID, filters string, pageSize int, pageToken string) ([]*pb.Note, string, error) {
	var rows *sql.Rows
	id := decryptInt64(pageToken, pg.paginationKey, 0)
	rows, err := pg.DB.Query(listNotes, pID, pageSize, id)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to list Notes from database")
	}
	ns := []*pb.Note{}
	var lastId int64
	for rows.Next() {
		var data string
		err := rows.Scan(&lastId, &data)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to scan Notes row")
		}
		var n pb.Note
		proto.UnmarshalText(data, &n)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to unmarshal Note from database")
		}
		ns = append(ns, &n)
	}
	encryptedPage, err := encryptInt64(lastId, pg.paginationKey)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to paginate projects")
	}
	return ns, encryptedPage, nil
}

// ListNoteOccurrences returns up to pageSize number of occcurrences on the particular note (nID)
// for this project (pID) projects beginning at pageToken (or from start if pageToken is the emtpy string).
func (pg *pgSQLStore) ListNoteOccurrences(pID, nID, filters string, pageSize int, pageToken string) ([]*pb.Occurrence, string, error) {
	// Verify that note exists
	if _, err := pg.GetNote(pID, nID); err != nil {
		return nil, "", err
	}
	var rows *sql.Rows
	id := decryptInt64(pageToken, pg.paginationKey, 0)
	rows, err := pg.DB.Query(listNoteOccurrences, pID, nID, pageSize, id)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to list Occurrences from database")
	}
	os := []*pb.Occurrence{}
	var lastId int64
	for rows.Next() {
		var data string
		err := rows.Scan(&lastId, &data)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to scan Occurrences row")
		}
		var o pb.Occurrence
		proto.UnmarshalText(data, &o)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to unmarshal Occurrence from database")
		}
		os = append(os, &o)
	}
	encryptedPage, err := encryptInt64(lastId, pg.paginationKey)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to paginate projects")
	}
	return os, encryptedPage, nil
}

// GetOperation returns the operation with pID and oID
func (pg *pgSQLStore) GetOperation(pID, opID string) (*opspb.Operation, error) {
	var data string
	err := pg.DB.QueryRow(searchOperation, pID, opID).Scan(&data)
	switch {
	case err == sql.ErrNoRows:
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q/%q does not Exist", pID, opID))
	case err != nil:
		return nil, status.Error(codes.Internal, "Failed to query Operation from database")
	}
	var op opspb.Operation
	proto.UnmarshalText(data, &op)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to unmarshal Operation from database")
	}
	return &op, nil
}

// CreateOperation adds the specified operation
func (pg *pgSQLStore) CreateOperation(o *opspb.Operation) error {
	pID, opID, err := name.ParseOperation(o.Name)
	if err != nil {
		log.Printf("Invalid operation name: %v", o.Name)
		return status.Error(codes.InvalidArgument, "Invalid operation name")
	}
	_, err = pg.DB.Exec(insertOperation, pID, opID, proto.MarshalTextString(o))
	if err, ok := err.(*pq.Error); ok {
		// Check for unique_violation
		if err.Code == "23505" {
			return status.Error(codes.AlreadyExists, fmt.Sprintf("Operation with name %q/%q already exists", pID, opID))
		} else {
			log.Println("Failed to insert Operation in database", err)
			return status.Error(codes.Internal, "Failed to insert Operation in database")
		}
	}
	return nil
}

// DeleteOperation deletes the operation with the given pID and oID
func (pg *pgSQLStore) DeleteOperation(pID, opID string) error {
	result, err := pg.DB.Exec(deleteOperation, pID, opID)
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Operation from database")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to delete Operation from database")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q/%q does not Exist", pID, opID))
	}
	return nil
}

// UpdateOperation updates the existing operation with the given pID and nID
func (pg *pgSQLStore) UpdateOperation(pID, opID string, op *opspb.Operation) error {
	result, err := pg.DB.Exec(updateOperation, pID, opID, proto.MarshalTextString(op))
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Operation")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return status.Error(codes.Internal, "Failed to update Operation")
	}
	if count == 0 {
		return status.Error(codes.NotFound, fmt.Sprintf("Operation with name %q/%q does not Exist", pID, opID))
	}
	return nil
}

// ListOperations returns up to pageSize number of operations for this project (pID) beginning
// at pageToken (or from start if pageToken is the emtpy string).
func (pg *pgSQLStore) ListOperations(pID, filters string, pageSize int, pageToken string) ([]*opspb.Operation, string, error) {
	var rows *sql.Rows
	id := decryptInt64(pageToken, pg.paginationKey, 0)
	rows, err := pg.DB.Query(listOperations, pID, pageSize, id)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to list Operations from database")
	}
	ops := []*opspb.Operation{}
	var lastId int64
	for rows.Next() {
		var data string
		err := rows.Scan(&lastId, &data)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to scan Operations row")
		}
		var op opspb.Operation
		proto.UnmarshalText(data, &op)
		if err != nil {
			return nil, "", status.Error(codes.Internal, "Failed to unmarshal Operation from database")
		}
		ops = append(ops, &op)
	}
	encryptedPage, err := encryptInt64(lastId, pg.paginationKey)
	if err != nil {
		return nil, "", status.Error(codes.Internal, "Failed to paginate projects")
	}
	return ops, encryptedPage, nil
}

// Encrypt int64 using provided key
func encryptInt64(v int64, key string) (string, error) {
	k, err := fernet.DecodeKey(key)
	if err != nil {
		return "", err
	}
	bytes, err := fernet.EncryptAndSign([]byte(strconv.FormatInt(v, 10)), k)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Decrypts encrypted int64 using provided key. Returns defaultValue if decryption fails.
func decryptInt64(encrypted string, key string, defaultValue int64) int64 {
	k, err := fernet.DecodeKey(key)
	if err != nil {
		return defaultValue
	}
	bytes := fernet.VerifyAndDecrypt([]byte(encrypted), time.Hour, []*fernet.Key{k})
	if bytes == nil {
		return defaultValue
	}
	decryptedValue, err := strconv.ParseInt(string(bytes), 10, 64)
	if err != nil {
		return defaultValue
	}
	return decryptedValue
}
