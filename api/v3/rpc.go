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
	"sync"

	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/coreos/clair"
	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/pagination"
)

func newRPCErrorWithClairError(code codes.Code, err error) error {
	return status.Errorf(code, "clair error reason: '%s'", err.Error())
}

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
	blobFormat := req.GetFormat()
	if !imagefmt.IsSupported(blobFormat) {
		return nil, status.Error(codes.InvalidArgument, "image blob format is not supported")
	}

	clairStatus, err := GetClairStatus(s.Store)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// check if the ancestry is already processed; if not we build the ancestry again.
	layerHashes := make([]string, len(req.Layers))
	for i, layer := range req.Layers {
		layerHashes[i] = layer.GetHash()
	}

	found, err := clair.IsAncestryCached(s.Store, req.AncestryName, layerHashes)
	if err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	if found {
		return &pb.PostAncestryResponse{Status: clairStatus}, nil
	}

	builder := clair.NewAncestryBuilder(clair.EnabledDetectors())
	layerMap := map[string]*database.Layer{}
	layerMapLock := sync.RWMutex{}
	g, analyzerCtx := errgroup.WithContext(ctx)
	for i := range req.Layers {
		layer := req.Layers[i]
		if _, ok := layerMap[layer.Hash]; !ok {
			layerMap[layer.Hash] = nil
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

			g.Go(func() error {
				clairLayer, err := clair.AnalyzeLayer(analyzerCtx, s.Store, layer.Hash, req.Format, layer.Path, layer.Headers)
				if err != nil {
					return err
				}

				layerMapLock.Lock()
				layerMap[layer.Hash] = clairLayer
				layerMapLock.Unlock()

				return nil
			})
		}
	}

	if err = g.Wait(); err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	for _, layer := range req.Layers {
		builder.AddLeafLayer(layerMap[layer.Hash])
	}

	if err := clair.SaveAncestry(s.Store, builder.Ancestry(req.AncestryName)); err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	return &pb.PostAncestryResponse{Status: clairStatus}, nil
}

// GetAncestry implements retrieving an ancestry via the Clair gRPC service.
func (s *AncestryServer) GetAncestry(ctx context.Context, req *pb.GetAncestryRequest) (*pb.GetAncestryResponse, error) {
	name := req.GetAncestryName()
	if name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ancestry name should not be empty")
	}

	ancestry, ok, err := database.FindAncestryAndRollback(s.Store, name)
	if err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	if !ok {
		return nil, status.Errorf(codes.NotFound, "requested ancestry '%s' is not found", req.GetAncestryName())
	}

	pbAncestry := &pb.GetAncestryResponse_Ancestry{
		Name:      ancestry.Name,
		Detectors: pb.DetectorsFromDatabaseModel(ancestry.By),
	}

	for _, layer := range ancestry.Layers {
		pbLayer, err := s.GetPbAncestryLayer(layer)
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

	dbNotification, ok, err := database.FindVulnerabilityNotificationAndRollback(
		s.Store,
		req.GetName(),
		int(req.GetLimit()),
		pagination.Token(req.GetOldVulnerabilityPage()),
		pagination.Token(req.GetNewVulnerabilityPage()),
	)

	if err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	if !ok {
		return nil, status.Errorf(codes.NotFound, "requested notification '%s' is not found", req.GetName())
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

	found, err := database.MarkNotificationAsReadAndCommit(s.Store, req.GetName())
	if err != nil {
		return nil, newRPCErrorWithClairError(codes.Internal, err)
	}

	if !found {
		return nil, status.Errorf(codes.NotFound, "requested notification '%s' is not found", req.GetName())
	}

	return &pb.MarkNotificationAsReadResponse{}, nil
}
