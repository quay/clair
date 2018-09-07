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
		Listers:   clair.Processors.Listers,
		Detectors: clair.Processors.Detectors,
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
func GetPbAncestryLayer(session database.Session, layer database.AncestryLayer) (*pb.GetAncestryResponse_AncestryLayer, error) {
	pbLayer := &pb.GetAncestryResponse_AncestryLayer{
		Layer: &pb.Layer{
			Hash: layer.Hash,
		},
	}

	var (
		features []database.NullableAffectedNamespacedFeature
		err      error
	)

	if features, err = session.FindAffectedNamespacedFeatures(layer.DetectedFeatures); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	for _, feature := range features {
		if !feature.Valid {
			return nil, status.Error(codes.Internal, "ancestry feature is not found")
		}

		var (
			pbFeature = pb.NamespacedFeatureFromDatabaseModel(feature.NamespacedFeature)
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

	return pbLayer, nil
}
