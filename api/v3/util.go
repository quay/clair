package v3

import (
	"github.com/coreos/clair"
	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
	"github.com/golang/protobuf/ptypes"
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
