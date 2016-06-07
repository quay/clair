package cmd

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/artyom/untar"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/dockerdist"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
	"github.com/spf13/cobra"

	dockercli "github.com/fsouza/go-dockerclient"
)

var pushDockerCmd = &cobra.Command{
	Use:   "push-docker IMAGE",
	Short: "Push Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Printf("clairctl: \"push\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		startLocalServer()

		imageName := args[0]
		if !docker.IsLocal {

			image, manifest, err := dockerdist.DownloadManifest(imageName, true)

			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing local image %q: %v", imageName, err)
			}
			// Ensure that the manifest type is supported.
			switch manifest.(type) {
			case *schema1.SignedManifest:
				break

			default:
				fmt.Println(errInternalError)
				logrus.Fatalf("only v1 manifests are currently supported")
			}
			v1manifest := manifest.(*schema1.SignedManifest)

			if err := dockerdist.Push(image, *v1manifest); err != nil {
				if err != nil {
					fmt.Println(errInternalError)
					logrus.Fatalf("pushing image %q: %v", imageName, err)
				}
			}

		} else {
			named, err := reference.ParseNamed(imageName)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("pushing image %q: %v", imageName, err)
			}
			p, err := save(named)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("saving image %q: %v", imageName, err)
			}
			m, err := historyFromManifest(p)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("reading manifest %q: %v", imageName, err)
			}

			for _, layer := range m.FSLayers {
				fmt.Println("ID: ", layer.BlobSum.String())
			}
			// var err error
			// image, err = docker.Parse(imageName)
			// if err != nil {
			// 	fmt.Println(errInternalError)
			// 	logrus.Fatalf("parsing local image %q: %v", imageName, err)
			// }
			// err = docker.Prepare(&image)
			// logrus.Debugf("prepared image layers: %d", len(image.FsLayers))
			// if err != nil {
			// 	fmt.Println(errInternalError)
			// 	logrus.Fatalf("preparing local image %q from history: %v", imageName, err)
			// }
			// logrus.Info("Pushing Image [OLD WAY] should be deprecated")
			// if err := docker.Push(image); err != nil {
			// 	if err != nil {
			// 		fmt.Println(errInternalError)
			// 		logrus.Fatalf("pushing image %q: %v", imageName, err)
			// 	}
			// }
		}

		fmt.Printf("%v has been pushed to Clair\n", imageName)
	},
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
		fmt.Println(strings.TrimSuffix(layer, "/layer.tar"))
		d, err := digest.ParseDigest("sha256:" + strings.TrimSuffix(layer, "/layer.tar"))
		if err != nil {
			return nil, err
		}
		m.FSLayers = append(m.FSLayers, schema1.FSLayer{BlobSum: d})
	}

	return &m, nil
}

func save(image reference.Named) (string, error) {

	imageName := image.Name()
	path := config.TmpLocal() + "/" + strings.Split(imageName, ":")[0] + "/blobs"

	if _, err := os.Stat(path); os.IsExist(err) {
		err := os.RemoveAll(path)
		if err != nil {
			return "", err
		}
	}

	err := os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}

	logrus.Debugln("docker image to save: ", imageName)
	logrus.Debugln("saving in: ", path)

	// open output file
	fo, err := os.Create(path + "/output.tar")
	if err != nil {
		return "", err
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
	client, _ := dockercli.NewClient(endpoint)
	err = client.ExportImage(dockercli.ExportImageOptions{Name: imageName, OutputStream: w})
	if err != nil {
		return "", err
	}
	err = openAndUntar(path+"/output.tar", path)
	if err != nil {
		return "", err
	}

	err = os.Remove(path + "/output.tar")
	if err != nil {
		return "", err
	}
	return path, err
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

func init() {
	RootCmd.AddCommand(pushDockerCmd)
	pushDockerCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}
