package v3

import (
	"github.com/coreos/clair"
	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetClairStatus retrieves the current status of Clair and wrap it inside
// protobuf struct.
func GetClairStatus(store database.Datastore) (*pb.ClairStatus, error) {
	status := &pb.ClairStatus{
		Detectors: pb.DetectorsFromDatabaseModel(clair.EnabledDetectors),
	}

	t, firstUpdate, err := clair.GetLastUpdateTime(store)
	if err != nil {
		return nil, err
	}
	if firstUpdate {
		return status, nil
	}

	status.LastUpdateTime, err = ptypes.TimestampProto(t)
	if err != nil {
		return nil, err
	}
	return status, nil
}

// GetPbAncestryLayer retrieves an ancestry layer with vulnerabilities and
// features in an ancestry based on the provided database layer.
func GetPbAncestryLayer(tx database.Session, layer database.AncestryLayer) (*pb.GetAncestryResponse_AncestryLayer, error) {
	pbLayer := &pb.GetAncestryResponse_AncestryLayer{
		Layer: &pb.Layer{
			Hash: layer.Hash,
		},
	}

	features := layer.GetFeatures()
	affectedFeatures, err := tx.FindAffectedNamespacedFeatures(features)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// NOTE(sidac): It's quite inefficient, but the easiest way to implement
	// this feature for now, we should refactor the implementation if there's
	// any performance issue. It's expected that the number of features is less
	// than 1000.
	for _, feature := range affectedFeatures {
		if !feature.Valid {
			return nil, status.Error(codes.Internal, "ancestry feature is not found")
		}

		for _, detectedFeature := range layer.Features {
			if detectedFeature.NamespacedFeature != feature.NamespacedFeature {
				continue
			}

			var (
				pbFeature = pb.NamespacedFeatureFromDatabaseModel(detectedFeature)
				pbVuln    *pb.Vulnerability
				err       error
			)

			for _, vuln := range feature.AffectedBy {
				if pbVuln, err = pb.VulnerabilityWithFixedInFromDatabaseModel(vuln); err != nil {
					return nil, status.Error(codes.Internal, err.Error())
				}

				pbFeature.Vulnerabilities = append(pbFeature.Vulnerabilities, pbVuln)
			}

			pbLayer.DetectedFeatures = append(pbLayer.DetectedFeatures, pbFeature)
		}
	}

	return pbLayer, nil
}
