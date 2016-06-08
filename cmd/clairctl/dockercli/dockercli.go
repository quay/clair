package dockercli

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/artyom/untar"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"

	dockerclient "github.com/fsouza/go-dockerclient"
)

//Save local images to tmp folder
func Save(image reference.Named) (*schema1.SignedManifest, error) {

	imageName := image.Name()
	path := config.TmpLocal() + "/" + strings.Split(imageName, ":")[0] + "/blobs"

	if _, err := os.Stat(path); os.IsExist(err) {
		err := os.RemoveAll(path)
		if err != nil {
			return nil, err
		}
	}

	err := os.MkdirAll(path, 0755)
	if err != nil {
		return nil, err
	}

	logrus.Debugln("docker image to save: ", imageName)
	logrus.Debugln("saving in: ", path)

	// open output file
	fo, err := os.Create(path + "/output.tar")
	if err != nil {
		return nil, err
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()
	// make a write buffer
	w := bufio.NewWriter(fo)

	endpoint := "unix:///var/run/docker.sock"
	client, _ := dockerclient.NewClient(endpoint)
	err = client.ExportImage(dockerclient.ExportImageOptions{Name: imageName, OutputStream: w})
	if err != nil {
		return nil, err
	}
	err = openAndUntar(path+"/output.tar", path)
	if err != nil {
		return nil, err
	}

	err = os.Remove(path + "/output.tar")
	if err != nil {
		return nil, err
	}
	return historyFromManifest(path)
}

func historyFromManifest(path string) (*schema1.SignedManifest, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// https://github.com/docker/docker/blob/master/image/tarexport/tarexport.go#L17
	type manifestItem struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return nil, err
	} else if len(manifest) != 1 {
		return nil, err
	}
	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	var m schema1.SignedManifest

	for _, layer := range manifest[0].Layers {
		var d digest.Digest
		d, err := digest.ParseDigest("sha256:" + strings.TrimSuffix(layer, "/layer.tar"))
		if err != nil {
			return nil, err
		}
		m.FSLayers = append(m.FSLayers, schema1.FSLayer{BlobSum: d})
	}

	return &m, nil
}

func openAndUntar(name, dst string) error {
	var rd io.Reader
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	rd = f
	if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tgz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gr.Close()
		rd = gr
	} else if strings.HasSuffix(name, ".bz2") {
		rd = bzip2.NewReader(f)
	}
	if err := os.MkdirAll(dst, os.ModeDir|os.ModePerm); err != nil {
		return err
	}
	// resetting umask is essential to have exact permissions on unpacked
	// files; it's not not put inside untar function as it changes
	// process-wide umask
	mask := syscall.Umask(0)
	defer syscall.Umask(mask)
	return untar.Untar(rd, dst)
}
