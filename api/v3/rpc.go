// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"fmt"

	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/coreos/clair"
	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/pagination"
)

// NotificationServer implements NotificationService interface for serving RPC.
type NotificationServer struct {
	Store database.Datastore
}

// AncestryServer implements AncestryService interface for serving RPC.
type AncestryServer struct {
	Store database.Datastore
}

// StatusServer implements StatusService interface for serving RPC.
type StatusServer struct {
	Store database.Datastore
}

// GetStatus implements getting the current status of Clair via the Clair service.
func (s *StatusServer) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	clairStatus, err := GetClairStatus(s.Store)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetStatusResponse{Status: clairStatus}, nil
}

// PostAncestry implements posting an ancestry via the Clair gRPC service.
func (s *AncestryServer) PostAncestry(ctx context.Context, req *pb.PostAncestryRequest) (*pb.PostAncestryResponse, error) {
	ancestryName := req.GetAncestryName()
	if ancestryName == "" {
		return nil, status.Error(codes.InvalidArgument, "ancestry name should not be empty")
	}

	layers := req.GetLayers()
	if len(layers) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ancestry should have at least one layer")
	}

	ancestryFormat := req.GetFormat()
	if ancestryFormat == "" {
		return nil, status.Error(codes.InvalidArgument, "ancestry format should not be empty")
	}

	ancestryLayers := []clair.LayerRequest{}
	for _, layer := range layers {
		if layer == nil {
			err := status.Error(codes.InvalidArgument, "ancestry layer is invalid")
			return nil, err
		}

		if layer.GetHash() == "" {
			return nil, status.Error(codes.InvalidArgument, "ancestry layer hash should not be empty")
		}

		if layer.GetPath() == "" {
			return nil, status.Error(codes.InvalidArgument, "ancestry layer path should not be empty")
		}

		ancestryLayers = append(ancestryLayers, clair.LayerRequest{
			Hash:    layer.Hash,
			Headers: layer.Headers,
			Path:    layer.Path,
		})
	}

	err := clair.ProcessAncestry(s.Store, ancestryFormat, ancestryName, ancestryLayers)
	if err != nil {
		return nil, status.Error(codes.Internal, "ancestry is failed to be processed: "+err.Error())
	}

	clairStatus, err := GetClairStatus(s.Store)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.PostAncestryResponse{Status: clairStatus}, nil
}

// GetAncestry implements retrieving an ancestry via the Clair gRPC service.
func (s *AncestryServer) GetAncestry(ctx context.Context, req *pb.GetAncestryRequest) (*pb.GetAncestryResponse, error) {
	name := req.GetAncestryName()
	if name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ancestry name should not be empty")
	}

	tx, err := s.Store.Begin()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	defer tx.Rollback()

	ancestry, ok, err := tx.FindAncestry(name)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("requested ancestry '%s' is not found", req.GetAncestryName()))
	}

	pbAncestry := &pb.GetAncestryResponse_Ancestry{
		Name:      ancestry.Name,
		Detectors: pb.DetectorsFromDatabaseModel(ancestry.By),
	}

	for _, layer := range ancestry.Layers {
		pbLayer, err := GetPbAncestryLayer(tx, layer)
		if err != nil {
			return nil, err
		}

		pbAncestry.Layers = append(pbAncestry.Layers, pbLayer)
	}

	pbClairStatus, err := GetClairStatus(s.Store)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetAncestryResponse{
		Status:   pbClairStatus,
		Ancestry: pbAncestry,
	}, nil
}

// GetNotification implements retrieving a notification via the Clair gRPC
// service.
func (s *NotificationServer) GetNotification(ctx context.Context, req *pb.GetNotificationRequest) (*pb.GetNotificationResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "notification name should not be empty")
	}

	if req.GetLimit() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "notification page limit should not be empty or less than 1")
	}

	tx, err := s.Store.Begin()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer tx.Rollback()

	dbNotification, ok, err := tx.FindVulnerabilityNotification(
		req.GetName(),
		int(req.GetLimit()),
		pagination.Token(req.GetOldVulnerabilityPage()),
		pagination.Token(req.GetNewVulnerabilityPage()),
	)

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("requested notification '%s' is not found", req.GetName()))
	}

	notification, err := pb.NotificationFromDatabaseModel(dbNotification)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetNotificationResponse{Notification: notification}, nil
}

// MarkNotificationAsRead implements deleting a notification via the Clair gRPC
// service.
func (s *NotificationServer) MarkNotificationAsRead(ctx context.Context, req *pb.MarkNotificationAsReadRequest) (*pb.MarkNotificationAsReadResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "notification name should not be empty")
	}

	tx, err := s.Store.Begin()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	defer tx.Rollback()
	err = tx.DeleteNotification(req.GetName())
	if err == commonerr.ErrNotFound {
		return nil, status.Error(codes.NotFound, "requested notification \""+req.GetName()+"\" is not found")
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.MarkNotificationAsReadResponse{}, nil
}
