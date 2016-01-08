package pgsql

import (
	"database/sql"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/guregu/null/zero"
)

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
	// Find the layer
	var layer database.Layer
	var parentID zero.Int
	var parentName zero.String
	var namespaceID zero.Int
	var namespaceName sql.NullString

	err := pgSQL.QueryRow(getQuery("s_layer"), name).
		Scan(&layer.ID, &layer.Name, &layer.EngineVersion, &parentID, &parentName, &namespaceID,
		&namespaceName)

	if err == sql.ErrNoRows {
		return layer, cerrors.ErrNotFound
	}
	if err != nil {
		return layer, err
	}

	if !parentID.IsZero() {
		layer.Parent = &database.Layer{
			Model: database.Model{ID: int(parentID.Int64)},
			Name:  parentName.String,
		}
	}
	if !namespaceID.IsZero() {
		layer.Namespace = &database.Namespace{
			Model: database.Model{ID: int(namespaceID.Int64)},
			Name:  namespaceName.String,
		}
	}

	// Find its features
	if withFeatures || withVulnerabilities {
		featureVersions, err := pgSQL.getLayerFeatureVersions(layer.ID, !withFeatures)
		if err != nil {
			return layer, err
		}
		layer.Features = featureVersions

		if withVulnerabilities {
			// Load the vulnerabilities that affect the FeatureVersions.
			err := pgSQL.loadAffectedBy(layer.Features)
			if err != nil {
				return layer, err
			}
		}
	}

	return layer, nil
}

// getLayerFeatureVersions returns list of database.FeatureVersion that a database.Layer has.
// if idOnly is specified, the returned structs will only have their ID filled. Otherwise,
// it also gets their versions, feature's names, feature's namespace's names.
func (pgSQL *pgSQL) getLayerFeatureVersions(layerID int, idOnly bool) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	// Build query
	var query string
	if idOnly {
		query = getQuery("s_layer_featureversion_id_only")
	} else {
		query = getQuery("s_layer_featureversion")
	}

	// Query
	rows, err := pgSQL.Query(query, layerID)
	if err != nil && err != sql.ErrNoRows {
		return featureVersions, err
	}
	defer rows.Close()

	// Scan query
	var modification string
	mapFeatureVersions := make(map[int]database.FeatureVersion)
	for rows.Next() {
		var featureVersion database.FeatureVersion

		if idOnly {
			err = rows.Scan(&featureVersion.ID, &modification)
			if err != nil {
				return featureVersions, err
			}
		} else {
			err = rows.Scan(&featureVersion.ID, &modification, &featureVersion.Feature.Namespace.ID,
				&featureVersion.Feature.Namespace.Name, &featureVersion.Feature.ID,
				&featureVersion.Feature.Name, &featureVersion.ID, &featureVersion.Version)
			if err != nil {
				return featureVersions, err
			}
		}

		// Do transitive closure
		switch modification {
		case "add":
			mapFeatureVersions[featureVersion.ID] = featureVersion
		case "del":
			delete(mapFeatureVersions, featureVersion.ID)
		default:
			log.Warningf("unknown Layer_diff_FeatureVersion's modification: %s", modification)
			return featureVersions, database.ErrInconsistent
		}
	}
	if err = rows.Err(); err != nil {
		return featureVersions, err
	}

	// Build result by converting our map to a slice
	for _, featureVersion := range mapFeatureVersions {
		featureVersions = append(featureVersions, featureVersion)
	}

	return featureVersions, nil
}

// loadAffectedBy returns the list of database.Vulnerability that affect the given
// FeatureVersion.
func (pgSQL *pgSQL) loadAffectedBy(featureVersions []database.FeatureVersion) error {
	if len(featureVersions) == 0 {
		return nil
	}

	// Construct list of FeatureVersion IDs, we will do a single query
	featureVersionIDs := make([]int, 0, len(featureVersions))
	for i := 0; i < len(featureVersions); i++ {
		featureVersionIDs = append(featureVersionIDs, featureVersions[i].ID)
	}

	rows, err := pgSQL.Query(getQuery("s_featureversions_vulnerabilities"),
		buildInputArray(featureVersionIDs))
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	defer rows.Close()

	vulnerabilities := make(map[int][]database.Vulnerability, len(featureVersions))
	var featureversionID int
	for rows.Next() {
		var vulnerability database.Vulnerability
		err := rows.Scan(&featureversionID, &vulnerability.ID, &vulnerability.Name,
			&vulnerability.Description, &vulnerability.Link, &vulnerability.Severity,
			&vulnerability.Namespace.Name, &vulnerability.FixedBy)
		if err != nil {
			return err
		}
		vulnerabilities[featureversionID] = append(vulnerabilities[featureversionID], vulnerability)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// Assign vulnerabilities to every FeatureVersions
	for i := 0; i < len(featureVersions); i++ {
		featureVersions[i].AffectedBy = vulnerabilities[featureVersions[i].ID]
	}

	return nil
}

// InsertLayer insert a single layer in the database
//
// The Name and EngineVersion fields are required.
// The Parent, Namespace, Features are optional.
// However, please note that the Parent field, if provided, is expected to have been retrieved
// using FindLayer with its Features.
//
// The Name must be unique for two different layers.
//
// If the Layer already exists and the EngineVersion value of the inserted layer is higher than the
// stored value, the EngineVersion, the Namespace and the Feature list will be updated.
//
// Internally, only Feature additions/removals are stored for each layer. If a layer has a parent,
// the Feature list will be compared to the parent's Feature list and the difference will be stored.
// Note that when the Namespace of a layer differs from its parent, it is expected that several
// Feature that were already included a parent will have their Namespace updated as well
// (happens when Feature detectors relies on the detected layer Namespace). However, if the listed
// Feature has the same Name/Version as its parent, InsertLayer considers that the Feature hasn't
// been modified.
// TODO(Quentin-M): This behavior should be implemented at the Feature detectors level.
func (pgSQL *pgSQL) InsertLayer(layer database.Layer) error {
	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return cerrors.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, true, false)
	if err != nil && err != cerrors.ErrNotFound {
		return err
	} else if err == nil {
		layer.ID = existingLayer.ID
	}

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}

	// Find or insert namespace if provided.
	var namespaceID zero.Int
	if layer.Namespace != nil {
		n, err := pgSQL.insertNamespace(*layer.Namespace)
		if err != nil {
			tx.Rollback()
			return err
		}
		namespaceID = zero.IntFrom(int64(n))
	} else if layer.Namespace == nil && layer.Parent != nil {
		// Import the Namespace from the parent if it has one and this layer doesn't specify one.
		if layer.Parent.Namespace != nil {
			namespaceID = zero.IntFrom(int64(layer.Parent.Namespace.ID))
		}
	}

	if layer.ID == 0 {
		// Insert a new layer.
		var parentID zero.Int
		if layer.Parent != nil {
			if layer.Parent.ID == 0 {
				log.Warning("Parent is expected to be retrieved from database when inserting a layer.")
				return cerrors.NewBadRequestError("Parent is expected to be retrieved from database when inserting a layer.")
			}

			parentID = zero.IntFrom(int64(layer.Parent.ID))
		}

		err = tx.QueryRow(getQuery("i_layer"), layer.Name, layer.EngineVersion, parentID, namespaceID).
			Scan(&layer.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine verison, do nothing.
			return nil
		}

		// Update an existing layer.
		_, err = tx.Exec(getQuery("u_layer"), layer.ID, layer.EngineVersion, namespaceID)
		if err != nil {
			tx.Rollback()
			return err
		}

		// Remove all existing Layer_diff_FeatureVersion.
		_, err = tx.Exec(getQuery("r_layer_diff_featureversion"), layer.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Update Layer_diff_FeatureVersion now.
	err = pgSQL.updateDiffFeatureVersions(tx, &layer, &existingLayer)
	if err != nil {
		return err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

func (pgSQL *pgSQL) updateDiffFeatureVersions(tx *sql.Tx, layer, existingLayer *database.Layer) error {
	// add and del are the FeatureVersion diff we should insert.
	var add []database.FeatureVersion
	var del []database.FeatureVersion

	if layer.Parent == nil {
		// There is no parent, every Features are added.
		add = append(add, layer.Features...)
	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

		// Build name:version strctures.
		layerFeaturesMapNV, layerFeaturesNV := createNV(layer.Features)
		parentLayerFeaturesMapNV, parentLayerFeaturesNV := createNV(layer.Parent.Features)

		// Calculate the added and deleted FeatureVersions name:version.
		addNV := utils.CompareStringLists(layerFeaturesNV, parentLayerFeaturesNV)
		delNV := utils.CompareStringLists(parentLayerFeaturesNV, layerFeaturesNV)

		// Fill the structures containing the added and deleted FeatureVersions
		for _, nv := range addNV {
			add = append(add, *layerFeaturesMapNV[nv])
		}
		for _, nv := range delNV {
			del = append(del, *parentLayerFeaturesMapNV[nv])
		}
	}

	// Insert FeatureVersions in the database.
	addIDs, err := pgSQL.insertFeatureVersions(add)
	if err != nil {
		return err
	}
	delIDs, err := pgSQL.insertFeatureVersions(del)
	if err != nil {
		return err
	}

	// Insert diff in the database.
	if len(addIDs) > 0 {
		_, err = tx.Exec(getQuery("i_layer_diff_featureversion"), layer.ID, "add", buildInputArray(addIDs))
		if err != nil {
			return err
		}
	}
	if len(delIDs) > 0 {
		_, err = tx.Exec(getQuery("i_layer_diff_featureversion"), layer.ID, "del", buildInputArray(delIDs))
		if err != nil {
			return err
		}
	}

	return nil
}

func createNV(features []database.FeatureVersion) (map[string]*database.FeatureVersion, []string) {
	mapNV := make(map[string]*database.FeatureVersion, 0)
	sliceNV := make([]string, 0, len(features))

	for i := 0; i < len(features); i++ {
		featureVersion := &features[i]
		nv := featureVersion.Feature.Name + ":" + featureVersion.Version.String()
		mapNV[nv] = featureVersion
		sliceNV = append(sliceNV, nv)
	}

	return mapNV, sliceNV
}

func (pgSQL *pgSQL) DeleteLayer(name string) error {
	// TODO
	return nil
}
