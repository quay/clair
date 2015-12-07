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
	"testing"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/stretchr/testify/assert"
)

// TestInvalidLayers tries to insert invalid layers
func TestInvalidLayers(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	assert.Error(t, InsertLayer(&Layer{ID: ""})) // No ID
}

// TestLayerSimple inserts a single layer and ensures it can be retrieved and
// that methods works
func TestLayerSimple(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	// Insert a layer and find it back
	l1 := &Layer{ID: "l1", OS: "os1", InstalledPackagesNodes: []string{"p1", "p2"}, EngineVersion: 1}
	if assert.Nil(t, InsertLayer(l1)) {
		fl1, err := FindOneLayerByID(l1.ID, FieldLayerAll)
		if assert.Nil(t, err) && assert.NotNil(t, fl1) {
			// Saved = found
			assert.True(t, layerEqual(l1, fl1), "layers are not equal, expected %v, have %s", l1, fl1)

			// No parent
			p, err := fl1.Parent(FieldLayerAll)
			assert.Nil(t, err)
			assert.Nil(t, p)

			// AllPackages()
			pk, err := fl1.AllPackages()
			assert.Nil(t, err)
			if assert.Len(t, pk, 2) {
				assert.Contains(t, pk, l1.InstalledPackagesNodes[0])
				assert.Contains(t, pk, l1.InstalledPackagesNodes[1])
			}
			// OS()
			o, err := fl1.OperatingSystem()
			assert.Nil(t, err)
			assert.Equal(t, l1.OS, o)
		}

		// FindAllLayersByAddedPackageNodes
		al1, err := FindAllLayersByAddedPackageNodes([]string{"p1", "p3"}, FieldLayerAll)
		if assert.Nil(t, err) && assert.Len(t, al1, 1) {
			assert.Equal(t, al1[0].Node, l1.Node)
		}

		// Delete
		if assert.Nil(t, DeleteLayer(l1.ID)) {
			_, err := FindOneLayerByID(l1.ID, FieldLayerAll)
			assert.Equal(t, cerrors.ErrNotFound, err)
		}
	}
}

// TestLayerTree inserts a tree of layers and ensure that the tree lgoic works
func TestLayerTree(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	var layers []*Layer
	layers = append(layers, &Layer{ID: "l1"})
	layers = append(layers, &Layer{ID: "l2", ParentNode: layers[0].GetNode(), OS: "os2", InstalledPackagesNodes: []string{"p1", "p2"}})
	layers = append(layers, &Layer{ID: "l3", ParentNode: layers[1].GetNode()})                                                                                      // Repeat an empty layer archive (l1)
	layers = append(layers, &Layer{ID: "l4a", ParentNode: layers[2].GetNode(), InstalledPackagesNodes: []string{"p3"}, RemovedPackagesNodes: []string{"p1", "p4"}}) // p4 does not exists and thu can't actually be removed
	layers = append(layers, &Layer{ID: "l4b", ParentNode: layers[2].GetNode(), InstalledPackagesNodes: []string{}, RemovedPackagesNodes: []string{"p2", "p1"}})

	var flayers []*Layer
	ok := true
	for _, l := range layers {
		ok = ok && assert.Nil(t, InsertLayer(l))

		fl, err := FindOneLayerByID(l.ID, FieldLayerAll)
		ok = ok && assert.Nil(t, err)
		ok = ok && assert.NotNil(t, fl)
		flayers = append(flayers, fl)
	}
	if assert.True(t, ok) {
		// Start testing

		// l4a
		// Parent()
		fl4ap, err := flayers[3].Parent(FieldLayerAll)
		assert.Nil(t, err, "l4a should has l3 as parent")
		if assert.NotNil(t, fl4ap, "l4a should has l3 as parent") {
			assert.Equal(t, "l3", fl4ap.ID, "l4a should has l3 as parent")
		}

		// OS()
		fl4ao, err := flayers[3].OperatingSystem()
		assert.Nil(t, err, "l4a should inherits its OS from l2")
		assert.Equal(t, "os2", fl4ao, "l4a should inherits its OS from l2")
		// AllPackages()
		fl4apkg, err := flayers[3].AllPackages()
		assert.Nil(t, err)
		if assert.Len(t, fl4apkg, 2) {
			assert.Contains(t, fl4apkg, "p2")
			assert.Contains(t, fl4apkg, "p3")
		}

		// l4b
		// AllPackages()
		fl4bpkg, err := flayers[4].AllPackages()
		assert.Nil(t, err)
		assert.Len(t, fl4bpkg, 0)

		// Delete a layer in the middle of the tree.
		if assert.Nil(t, DeleteLayer(flayers[1].ID)) {
			for _, l := range layers[1:] {
				_, err := FindOneLayerByID(l.ID, FieldLayerAll)
				assert.Equal(t, cerrors.ErrNotFound, err)
			}
		}
	}
}

func TestLayerUpdate(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	l1 := &Layer{ID: "l1", OS: "os1", InstalledPackagesNodes: []string{"p1", "p2"}, RemovedPackagesNodes: []string{"p3", "p4"}, EngineVersion: 1}
	if assert.Nil(t, InsertLayer(l1)) {
		// Do not update layer content if the engine versions are equals
		l1b := &Layer{ID: "l1", OS: "os2", InstalledPackagesNodes: []string{"p1"}, RemovedPackagesNodes: []string{""}, EngineVersion: 1}
		if assert.Nil(t, InsertLayer(l1b)) {
			fl1b, err := FindOneLayerByID(l1.ID, FieldLayerAll)
			if assert.Nil(t, err) && assert.NotNil(t, fl1b) {
				assert.True(t, layerEqual(l1, fl1b), "layer contents are not equal, expected %v, have %s", l1, fl1b)
			}
		}

		// Update the layer content with new data and a higher engine version
		l1c := &Layer{ID: "l1", OS: "os2", InstalledPackagesNodes: []string{"p1", "p5"}, RemovedPackagesNodes: []string{"p6", "p7"}, EngineVersion: 2}
		if assert.Nil(t, InsertLayer(l1c)) {
			fl1c, err := FindOneLayerByID(l1c.ID, FieldLayerAll)
			if assert.Nil(t, err) && assert.NotNil(t, fl1c) {
				assert.True(t, layerEqual(l1c, fl1c), "layer contents are not equal, expected %v, have %s", l1c, fl1c)
			}
		}
	}
}

func layerEqual(expected, actual *Layer) bool {
	eq := true
	eq = eq && expected.Node == actual.Node
	eq = eq && expected.ID == actual.ID
	eq = eq && expected.ParentNode == actual.ParentNode
	eq = eq && expected.OS == actual.OS
	eq = eq && expected.EngineVersion == actual.EngineVersion
	eq = eq && len(utils.CompareStringLists(actual.SuccessorsNodes, expected.SuccessorsNodes)) == 0 && len(utils.CompareStringLists(expected.SuccessorsNodes, actual.SuccessorsNodes)) == 0
	eq = eq && len(utils.CompareStringLists(actual.RemovedPackagesNodes, expected.RemovedPackagesNodes)) == 0 && len(utils.CompareStringLists(expected.RemovedPackagesNodes, actual.RemovedPackagesNodes)) == 0
	eq = eq && len(utils.CompareStringLists(actual.InstalledPackagesNodes, expected.InstalledPackagesNodes)) == 0 && len(utils.CompareStringLists(expected.InstalledPackagesNodes, actual.InstalledPackagesNodes)) == 0
	return eq
}
