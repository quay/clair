package nvd

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/pkg/capnslog"
)

const (
	dataFeedURL     string = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.gz"
	dataFeedMetaURL string = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.meta"

	metadataKey string = "NVD"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/metadata_fetchers")
)

type NVDMetadataFetcher struct {
	localPath      string
	dataFeedHashes map[string]string
	lock           sync.Mutex

	metadata map[string]NVDMetadata
}

type NVDMetadata struct {
	CVSSv2 NVDmetadataCVSSv2
}

type NVDmetadataCVSSv2 struct {
	Vectors string
	Score   float64
}

func init() {
	updater.RegisterMetadataFetcher("NVD", &NVDMetadataFetcher{})
}

func (fetcher *NVDMetadataFetcher) Load(datastore database.Datastore) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	var err error
	fetcher.metadata = make(map[string]NVDMetadata)

	// Init if necessary.
	if fetcher.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if fetcher.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return cerrors.ErrFilesystem
		}

		fetcher.dataFeedHashes = make(map[string]string)
	}

	// Get data feeds.
	dataFeedReaders, dataFeedHashes, err := getDataFeeds(fetcher.dataFeedHashes, fetcher.localPath)
	if err != nil {
		return err
	}
	fetcher.dataFeedHashes = dataFeedHashes

	// Parse data feeds.
	for dataFeedName, dataFeedReader := range dataFeedReaders {
		var nvd nvd
		if err = xml.NewDecoder(dataFeedReader).Decode(&nvd); err != nil {
			log.Errorf("could not decode NVD data feed '%s': %s", dataFeedName, err)
			return cerrors.ErrCouldNotParse
		}

		// For each entry of this data feed:
		for _, nvdEntry := range nvd.Entries {
			// Create metadata entry.
			if metadata := nvdEntry.Metadata(); metadata != nil {
				fetcher.metadata[nvdEntry.Name] = *metadata
			}
		}

		dataFeedReader.Close()
	}

	return nil
}

func (fetcher *NVDMetadataFetcher) AddMetadata(vulnerability *updater.VulnerabilityWithLock) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvdMetadata, ok := fetcher.metadata[vulnerability.Name]; ok {
		vulnerability.Lock.Lock()
		defer vulnerability.Lock.Unlock()

		// Create Metadata map if necessary.
		if vulnerability.Metadata == nil {
			vulnerability.Metadata = make(map[string]interface{})
		}

		vulnerability.Metadata[metadataKey] = nvdMetadata
	}

	return nil
}

func (fetcher *NVDMetadataFetcher) Unload() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	fetcher.metadata = nil
}

func (fetcher *NVDMetadataFetcher) Clean() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if fetcher.localPath != "" {
		os.RemoveAll(fetcher.localPath)
	}
}

func getDataFeeds(dataFeedHashes map[string]string, localPath string) (map[string]NestedReadCloser, map[string]string, error) {
	var dataFeedNames []string
	for y := 2002; y <= time.Now().Year(); y++ {
		dataFeedNames = append(dataFeedNames, strconv.Itoa(y))
	}

	// Get hashes for these feeds.
	for _, dataFeedName := range dataFeedNames {
		hash, err := getHashFromMetaURL(fmt.Sprintf(dataFeedMetaURL, dataFeedName))
		if err != nil {
			log.Warningf("could get get NVD data feed hash '%s': %s", dataFeedName, err)

			// It's not a big deal, no need interrupt, we're just going to download it again then.
			continue
		}

		dataFeedHashes[dataFeedName] = hash
	}

	// Create io.Reader for every data feed.
	dataFeedReaders := make(map[string]NestedReadCloser)
	for _, dataFeedName := range dataFeedNames {
		fileName := localPath + dataFeedName + ".xml"

		if h, ok := dataFeedHashes[dataFeedName]; ok && h == dataFeedHashes[dataFeedName] {
			// The hash is known, the disk should contains the feed. Try to read from it.
			if localPath != "" {
				if f, err := os.Open(fileName); err == nil {
					dataFeedReaders[dataFeedName] = NestedReadCloser{
						Reader:            f,
						NestedReadClosers: []io.ReadCloser{f},
					}
					continue
				}
			}

			// Download data feed.
			r, err := http.Get(fmt.Sprintf(dataFeedURL, dataFeedName))
			if err != nil {
				log.Errorf("could not download NVD data feed file '%s': %s", dataFeedName, err)
				return dataFeedReaders, dataFeedHashes, cerrors.ErrCouldNotDownload
			}

			// Un-gzip it.
			gr, err := gzip.NewReader(r.Body)
			if err != nil {
				log.Errorf("could not read NVD data feed file '%s': %s", dataFeedName, err)
				return dataFeedReaders, dataFeedHashes, cerrors.ErrCouldNotDownload
			}

			// Store it to a file at the same time if possible.
			if f, err := os.Create(fileName); err == nil {
				nrc := NestedReadCloser{
					Reader:            io.TeeReader(gr, f),
					NestedReadClosers: []io.ReadCloser{r.Body, gr, f},
				}
				dataFeedReaders[dataFeedName] = nrc
			} else {
				nrc := NestedReadCloser{
					Reader:            gr,
					NestedReadClosers: []io.ReadCloser{gr, r.Body},
				}
				dataFeedReaders[dataFeedName] = nrc

				log.Warningf("could not store NVD data feed to filesystem: %s", err)
			}
		}
	}

	return dataFeedReaders, dataFeedHashes, nil
}

func getHashFromMetaURL(metaURL string) (string, error) {
	r, err := http.Get(metaURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "sha256:") {
			return strings.TrimPrefix(line, "sha256:"), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.New("invalid .meta file format")
}
