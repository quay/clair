// Copyright 2015 clair authors
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

package database

import (
	"strconv"

	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/google/cayley/graph/path"
)

const (
	FieldLayerID            = "id"
	FieldLayerParent        = "parent"
	FieldLayerSuccessors    = "successors"
	FieldLayerOS            = "os"
	FieldLayerEngineVersion = "engineVersion"
	FieldLayerPackages      = "adds/removes"

	// These fields are not selectable and are for internal use only.
	fieldLayerIsValue           = "layer"
	fieldLayerInstalledPackages = "adds"
	fieldLayerRemovedPackages   = "removes"
)

var FieldLayerAll = []string{FieldLayerID, FieldLayerParent, FieldLayerSuccessors, FieldLayerOS, FieldLayerPackages, FieldLayerEngineVersion}

// Layer represents an unique container layer
type Layer struct {
	Node                   string `json:"-"`
	ID                     string
	ParentNode             string   `json:"-"`
	SuccessorsNodes        []string `json:"-"`
	OS                     string
	InstalledPackagesNodes []string `json:"-"`
	RemovedPackagesNodes   []string `json:"-"`
	EngineVersion          int
}

// GetNode returns the node name of a Layer
// Requires the key field: ID
func (l *Layer) GetNode() string {
	return fieldLayerIsValue + ":" + utils.Hash(l.ID)
}

// InsertLayer insert a single layer in the database
//
// ID, and EngineVersion fields are required.
// ParentNode, OS, InstalledPackagesNodes and RemovedPackagesNodes are optional,
// SuccessorsNodes is unnecessary.
//
// The ID MUST be unique for two different layers.
//
//
// If the Layer already exists, nothing is done, except if the provided engine
// version is higher than the existing one, in which case, the OS,
// InstalledPackagesNodes and RemovedPackagesNodes fields will be replaced.
//
// The layer should only contains the newly installed/removed packages
// There is no safeguard that prevents from marking a package as newly installed
// while it has already been installed in one of its parent.
func InsertLayer(layer *Layer) error {
	// Verify parameters
	if layer.ID == "" {
		log.Warning("could not insert a layer which has an empty ID")
		return cerrors.NewBadRequestError("could not insert a layer which has an empty ID")
	}

	// Create required data structures
	t := cayley.NewTransaction()
	layer.Node = layer.GetNode()

	// Try to find an existing layer
	existingLayer, err := FindOneLayerByNode(layer.Node, FieldLayerAll)
	if err != nil && err != cerrors.ErrNotFound {
		return err
	}

	if existingLayer != nil && existingLayer.EngineVersion >= layer.EngineVersion {
		// The layer exists and has an equal or higher engine verison, do nothing
		return nil
	}

	if existingLayer == nil {
		// Create case: add permanent nodes
		t.AddQuad(cayley.Triple(layer.Node, fieldIs, fieldLayerIsValue))
		t.AddQuad(cayley.Triple(layer.Node, FieldLayerID, layer.ID))
		t.AddQuad(cayley.Triple(layer.Node, FieldLayerParent, layer.ParentNode))
	} else {
		// Update case: remove everything before we add updated data
		t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerOS, existingLayer.OS))
		for _, pkg := range existingLayer.InstalledPackagesNodes {
			t.RemoveQuad(cayley.Triple(layer.Node, fieldLayerInstalledPackages, pkg))
		}
		for _, pkg := range existingLayer.RemovedPackagesNodes {
			t.RemoveQuad(cayley.Triple(layer.Node, fieldLayerRemovedPackages, pkg))
		}
		t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerEngineVersion, strconv.Itoa(existingLayer.EngineVersion)))
	}

	// Add OS/Packages
	t.AddQuad(cayley.Triple(layer.Node, FieldLayerOS, layer.OS))
	for _, pkg := range layer.InstalledPackagesNodes {
		t.AddQuad(cayley.Triple(layer.Node, fieldLayerInstalledPackages, pkg))
	}
	for _, pkg := range layer.RemovedPackagesNodes {
		t.AddQuad(cayley.Triple(layer.Node, fieldLayerRemovedPackages, pkg))
	}
	t.AddQuad(cayley.Triple(layer.Node, FieldLayerEngineVersion, strconv.Itoa(layer.EngineVersion)))

	// Apply transaction
	if err = store.ApplyTransaction(t); err != nil {
		log.Errorf("failed transaction (InsertLayer): %s", err)
		return ErrTransaction
	}

	return nil
}

// DeleteLayer deletes the specified layer and any child layers that are
// dependent on the specified layer.
func DeleteLayer(ID string) error {
	layer, err := FindOneLayerByID(ID, []string{})
	if err != nil {
		return err
	}
	return deleteLayerTreeFrom(layer.Node, nil)
}

func deleteLayerTreeFrom(node string, t *graph.Transaction) error {
	// Determine if that function call is the root call of the recursivity
	// And create transaction if its the case.
	root := (t == nil)
	if root {
		t = cayley.NewTransaction()
	}

	// Find layer.
	layer, err := FindOneLayerByNode(node, FieldLayerAll)
	if err != nil {
		// Ignore missing layer.
		return nil
	}

	// Remove all successor layers.
	for _, succNode := range layer.SuccessorsNodes {
		deleteLayerTreeFrom(succNode, t)
	}

	// Remove layer.
	t.RemoveQuad(cayley.Triple(layer.Node, fieldIs, fieldLayerIsValue))
	t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerID, layer.ID))
	t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerParent, layer.ParentNode))
	t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerOS, layer.OS))
	t.RemoveQuad(cayley.Triple(layer.Node, FieldLayerEngineVersion, strconv.Itoa(layer.EngineVersion)))
	for _, pkg := range layer.InstalledPackagesNodes {
		t.RemoveQuad(cayley.Triple(layer.Node, fieldLayerInstalledPackages, pkg))
	}
	for _, pkg := range layer.RemovedPackagesNodes {
		t.RemoveQuad(cayley.Triple(layer.Node, fieldLayerRemovedPackages, pkg))
	}

	// Apply transaction if root call.
	if root {
		if err = store.ApplyTransaction(t); err != nil {
			log.Errorf("failed transaction (deleteLayerTreeFrom): %s", err)
			return ErrTransaction
		}
	}

	return nil
}

// FindOneLayerByID finds and returns a single layer having the given ID,
// selecting the specified fields and hardcoding its ID
func FindOneLayerByID(ID string, selectedFields []string) (*Layer, error) {
	t := &Layer{ID: ID}
	l, err := FindOneLayerByNode(t.GetNode(), selectedFields)
	if err != nil {
		return nil, err
	}
	l.ID = ID
	return l, nil
}

// FindOneLayerByNode finds and returns a single package by its node, selecting the specified fields
func FindOneLayerByNode(node string, selectedFields []string) (*Layer, error) {
	l, err := toLayers(cayley.StartPath(store, node).Has(fieldIs, fieldLayerIsValue), selectedFields)
	if err != nil {
		return nil, err
	}
	if len(l) == 1 {
		return l[0], nil
	}
	if len(l) > 1 {
		log.Errorf("found multiple layers with identical node [Node: %s]", node)
		return nil, ErrInconsistent
	}

	return nil, cerrors.ErrNotFound
}

// FindAllLayersByAddedPackageNodes finds and returns all layers that add the
// given packages (by their nodes), selecting the specified fields
func FindAllLayersByAddedPackageNodes(nodes []string, selectedFields []string) ([]*Layer, error) {
	layers, err := toLayers(cayley.StartPath(store, nodes...).In(fieldLayerInstalledPackages), selectedFields)
	if err != nil {
		return []*Layer{}, err
	}
	return layers, nil
}

// FindAllLayersByPackageNode finds and returns all layers that have the given package (by its node), selecting the specified fields
// func FindAllLayersByPackageNode(node string, only map[string]struct{}) ([]*Layer, error) {
// 	var layers []*Layer
//
// 	// We need the successors field
// 	if only != nil {
// 		only[FieldLayerSuccessors] = struct{}{}
// 	}
//
// 	// Get all the layers which remove the package
// 	layersNodesRemoving, err := toValues(cayley.StartPath(store, node).In(fieldLayerRemovedPackages).Has(fieldIs, fieldLayerIsValue))
// 	if err != nil {
// 		return []*Layer{}, err
// 	}
// 	layersNodesRemovingMap := make(map[string]struct{})
// 	for _, l := range layersNodesRemoving {
// 		layersNodesRemovingMap[l] = struct{}{}
// 	}
//
// 	layersToBrowse, err := toLayers(cayley.StartPath(store, node).In(fieldLayerInstalledPackages).Has(fieldIs, fieldLayerIsValue), only)
// 	if err != nil {
// 		return []*Layer{}, err
// 	}
// 	for len(layersToBrowse) > 0 {
// 		var newLayersToBrowse []*Layer
// 		for _, layerToBrowse := range layersToBrowse {
// 			if _, layerRemovesPackage := layersNodesRemovingMap[layerToBrowse.Node]; !layerRemovesPackage {
// 				layers = append(layers, layerToBrowse)
// 				successors, err := layerToBrowse.Successors(only)
// 				if err != nil {
// 					return []*Layer{}, err
// 				}
// 				newLayersToBrowse = append(newLayersToBrowse, successors...)
// 			}
// 			layersToBrowse = newLayersToBrowse
// 		}
// 	}
//
// 	return layers, nil
// }

// toLayers converts a path leading to one or multiple layers to Layer structs,
// selecting the specified fields
func toLayers(path *path.Path, selectedFields []string) ([]*Layer, error) {
	var layers []*Layer

	saveFields(path, selectedFields, []string{FieldLayerSuccessors, FieldLayerPackages, fieldLayerInstalledPackages, fieldLayerRemovedPackages})
	it, _ := path.BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		layer := Layer{Node: store.NameOf(it.Result())}
		for _, selectedField := range selectedFields {
			switch selectedField {
			case FieldLayerID:
				layer.ID = store.NameOf(tags[FieldLayerID])
			case FieldLayerParent:
				layer.ParentNode = store.NameOf(tags[FieldLayerParent])
			case FieldLayerSuccessors:
				var err error
				layer.SuccessorsNodes, err = toValues(cayley.StartPath(store, layer.Node).In(FieldLayerParent))
				if err != nil {
					log.Errorf("could not get successors of layer %s: %s.", layer.Node, err.Error())
					return nil, err
				}
			case FieldLayerOS:
				layer.OS = store.NameOf(tags[FieldLayerOS])
			case FieldLayerPackages:
				var err error
				it, _ := cayley.StartPath(store, layer.Node).OutWithTags([]string{"predicate"}, fieldLayerInstalledPackages, fieldLayerRemovedPackages).BuildIterator().Optimize()
				defer it.Close()
				for cayley.RawNext(it) {
					tags := make(map[string]graph.Value)
					it.TagResults(tags)

					predicate := store.NameOf(tags["predicate"])
					if predicate == fieldLayerInstalledPackages {
						layer.InstalledPackagesNodes = append(layer.InstalledPackagesNodes, store.NameOf(it.Result()))
					} else if predicate == fieldLayerRemovedPackages {
						layer.RemovedPackagesNodes = append(layer.RemovedPackagesNodes, store.NameOf(it.Result()))
					}
				}
				if it.Err() != nil {
					log.Errorf("could not get installed/removed packages of layer %s: %s.", layer.Node, it.Err())
					return nil, err
				}
			case FieldLayerEngineVersion:
				layer.EngineVersion, _ = strconv.Atoi(store.NameOf(tags[FieldLayerEngineVersion]))
			default:
				panic("unknown selectedField")
			}
		}
		layers = append(layers, &layer)
	}
	if it.Err() != nil {
		log.Errorf("failed query in toLayers: %s", it.Err())
		return []*Layer{}, ErrBackendException
	}

	return layers, nil
}

// Successors find and returns all layers that define l as their parent,
// selecting the specified fields
// It requires that FieldLayerSuccessors field has been selected on l
// func (l *Layer) Successors(selectedFields []string) ([]*Layer, error) {
// 	if len(l.SuccessorsNodes) == 0 {
// 		return []*Layer{}, nil
// 	}
//
// 	return toLayers(cayley.StartPath(store, l.SuccessorsNodes...), only)
// }

// Parent find and returns the parent layer of l, selecting the specified fields
// It requires that FieldLayerParent field has been selected on l
func (l *Layer) Parent(selectedFields []string) (*Layer, error) {
	if l.ParentNode == "" {
		return nil, nil
	}

	parent, err := toLayers(cayley.StartPath(store, l.ParentNode), selectedFields)
	if err != nil {
		return nil, err
	}
	if len(parent) == 1 {
		return parent[0], nil
	}
	if len(parent) > 1 {
		log.Errorf("found multiple layers when getting parent layer of layer %s", l.ParentNode)
		return nil, ErrInconsistent
	}
	return nil, nil
}

// Sublayers find and returns all layers that compose l, selecting the specified
// fields
// It requires that FieldLayerParent field has been selected on l
// The base image comes first, and l is last
// func (l *Layer) Sublayers(selectedFields []string) ([]*Layer, error) {
// 	var sublayers []*Layer
//
// 	// We need the parent field
// 	if only != nil {
// 		only[FieldLayerParent] = struct{}{}
// 	}
//
// 	parent, err := l.Parent(only)
// 	if err != nil {
// 		return []*Layer{}, err
// 	}
// 	if parent != nil {
// 		parentSublayers, err := parent.Sublayers(only)
// 		if err != nil {
// 			return []*Layer{}, err
// 		}
// 		sublayers = append(sublayers, parentSublayers...)
// 	}
//
// 	sublayers = append(sublayers, l)
//
// 	return sublayers, nil
// }

// AllPackages computes the full list of packages that l has and return them as
// nodes.
// It requires that FieldLayerParent, FieldLayerContentInstalledPackages,
// FieldLayerContentRemovedPackages fields has been selected on l
func (l *Layer) AllPackages() ([]string, error) {
	var allPackages []string

	parent, err := l.Parent([]string{FieldLayerParent, FieldLayerPackages})
	if err != nil {
		return []string{}, err
	}
	if parent != nil {
		allPackages, err = parent.AllPackages()
		if err != nil {
			return []string{}, err
		}
	}

	return append(utils.CompareStringLists(allPackages, l.RemovedPackagesNodes), l.InstalledPackagesNodes...), nil
}

// OperatingSystem tries to find the Operating System of a layer using its
// parents.
// It requires that FieldLayerParent and FieldLayerOS fields has been
// selected on l
func (l *Layer) OperatingSystem() (string, error) {
	if l.OS != "" {
		return l.OS, nil
	}

	// Try from the parent
	parent, err := l.Parent([]string{FieldLayerParent, FieldLayerOS})
	if err != nil {
		return "", err
	}
	if parent != nil {
		return parent.OperatingSystem()
	}
	return "", nil
}
