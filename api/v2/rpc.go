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

package v2

import (
	"fmt"

	google_protobuf1 "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/coreos/clair"
	"github.com/coreos/clair/api/token"
	pb "github.com/coreos/clair/api/v2/clairpb"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/tarutil"
)

// NotificationServer implements NotificationService interface for serving RPC.
type NotificationServer struct {
	Store         database.Datastore
	PaginationKey string
}

// AncestryServer implements AncestryService interface for serving RPC.
type AncestryServer struct {
	Store database.Datastore
}

// PostAncestry implements posting an ancestry via the Clair gRPC service.
func (s *AncestryServer) PostAncestry(ctx context.Context, req *pb.PostAncestryRequest) (*pb.PostAncestryResponse, error) {
	ancestryName := req.GetAncestryName()
	if ancestryName == "" {
		return nil, status.Error(codes.InvalidArgument, "Failed to provide proper ancestry name")
	}

	layers := req.GetLayers()
	if len(layers) == 0 {
		return nil, status.Error(codes.InvalidArgument, "At least one layer should be provided for an ancestry")
	}

	var currentName, parentName, rootName string
	for i, layer := range layers {
		if layer == nil {
			err := status.Error(codes.InvalidArgument, "Failed to provide layer")
			return nil, s.rollBackOnError(err, currentName, rootName)
		}

		// TODO(keyboardnerd): after altering the database to support ancestry,
		// we should use the ancestry name and index as key instead of
		// the amalgamation of ancestry name of index
		// Hack: layer name is [ancestryName]-[index] except the tail layer,
		// tail layer name is [ancestryName]
		if i == len(layers)-1 {
			currentName = ancestryName
		} else {
			currentName = fmt.Sprintf("%s-%d", ancestryName, i)
		}

		// if rootName is unset, this is the first iteration over the layers and
		// the current layer is the root of the ancestry
		if rootName == "" {
			rootName = currentName
		}

		err := clair.ProcessLayer(s.Store, req.GetFormat(), currentName, parentName, layer.GetPath(), layer.GetHeaders())
		if err != nil {
			return nil, s.rollBackOnError(err, currentName, rootName)
		}

		// Now that the current layer is processed, set the parentName for the
		// next iteration.
		parentName = currentName
	}

	return &pb.PostAncestryResponse{
		EngineVersion: clair.Version,
	}, nil
}

// GetAncestry implements retrieving an ancestry via the Clair gRPC service.
func (s *AncestryServer) GetAncestry(ctx context.Context, req *pb.GetAncestryRequest) (*pb.GetAncestryResponse, error) {
	if req.GetAncestryName() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid get ancestry request")
	}

	// TODO(keyboardnerd): after altering the database to support ancestry, this
	// function is iteratively querying for for r.GetIndex() th parent of the
	// requested layer until the indexed layer is found or index is out of bound
	// this is a hack and will be replaced with one query
	ancestry, features, err := s.getAncestry(req.GetAncestryName(), req.GetWithFeatures(), req.GetWithVulnerabilities())
	if err == commonerr.ErrNotFound {
		return nil, status.Error(codes.NotFound, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetAncestryResponse{
		Ancestry: ancestry,
		Features: features,
	}, nil
}

// GetNotification implements retrieving a notification via the Clair gRPC
// service.
func (s *NotificationServer) GetNotification(ctx context.Context, req *pb.GetNotificationRequest) (*pb.GetNotificationResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "Failed to provide notification name")
	}

	if req.GetLimit() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "Failed to provide page limit")
	}

	page := database.VulnerabilityNotificationFirstPage
	pageToken := req.GetPage()
	if pageToken != "" {
		err := token.Unmarshal(pageToken, s.PaginationKey, &page)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid page format %s", err.Error())
		}
	} else {
		pageTokenBytes, err := token.Marshal(page, s.PaginationKey)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Failed to marshal token: %s", err.Error())
		}
		pageToken = string(pageTokenBytes)
	}

	dbNotification, nextPage, err := s.Store.GetNotification(req.GetName(), int(req.GetLimit()), page)
	if err == commonerr.ErrNotFound {
		return nil, status.Error(codes.NotFound, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	notification, err := pb.NotificationFromDatabaseModel(dbNotification, int(req.GetLimit()), pageToken, nextPage, s.PaginationKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetNotificationResponse{Notification: notification}, nil
}

// DeleteNotification implements deleting a notification via the Clair gRPC
// service.
func (s *NotificationServer) DeleteNotification(ctx context.Context, req *pb.DeleteNotificationRequest) (*google_protobuf1.Empty, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "Failed to provide notification name")
	}

	err := s.Store.DeleteNotification(req.GetName())
	if err == commonerr.ErrNotFound {
		return nil, status.Error(codes.NotFound, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &google_protobuf1.Empty{}, nil
}

// rollBackOnError handles server error and rollback whole ancestry insertion if
// any layer failed to be inserted.
func (s *AncestryServer) rollBackOnError(err error, currentLayerName, rootLayerName string) error {
	// if the current layer failed to be inserted and it's the root layer,
	// then the ancestry is not yet in the database.
	if currentLayerName != rootLayerName {
		errrb := s.Store.DeleteLayer(rootLayerName)
		if errrb != nil {
			return status.Errorf(codes.Internal, errrb.Error())
		}
		log.WithField("layer name", currentLayerName).Warnf("Can't process %s: roll back the ancestry", currentLayerName)
	}

	if err == tarutil.ErrCouldNotExtract ||
		err == tarutil.ErrExtractedFileTooBig ||
		err == clair.ErrUnsupported {
		return status.Errorf(codes.InvalidArgument, "unprocessable entity %s", err.Error())
	}

	if _, badreq := err.(*commonerr.ErrBadRequest); badreq {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	return status.Error(codes.Internal, err.Error())
}

// TODO(keyboardnerd): Remove this Legacy compability code once the database is
// revised.
// getAncestry returns an ancestry from database by getting all parents of a
// layer given the layer name, and the layer's feature list if
// withFeature/withVulnerability is turned on.
func (s *AncestryServer) getAncestry(name string, withFeature bool, withVulnerability bool) (ancestry *pb.Ancestry, features []*pb.Feature, err error) {
	var (
		layers = []*pb.Layer{}
		layer  database.Layer
	)
	ancestry = &pb.Ancestry{}

	layer, err = s.Store.FindLayer(name, withFeature, withVulnerability)
	if err != nil {
		return
	}

	if withFeature {
		for _, fv := range layer.Features {
			f, e := pb.FeatureFromDatabaseModel(fv, withVulnerability)
			if e != nil {
				err = e
				return
			}

			features = append(features, f)
		}
	}

	ancestry.Name = name
	ancestry.EngineVersion = int32(layer.EngineVersion)
	for name != "" {
		layer, err = s.Store.FindLayer(name, false, false)
		if err != nil {
			return
		}

		if layer.Parent != nil {
			name = layer.Parent.Name
		} else {
			name = ""
		}

		layers = append(layers, pb.LayerFromDatabaseModel(layer))
	}

	// reverse layers to make the root layer at the top
	for i, j := 0, len(layers)-1; i < j; i, j = i+1, j-1 {
		layers[i], layers[j] = layers[j], layers[i]
	}

	ancestry.Layers = layers
	return
}
