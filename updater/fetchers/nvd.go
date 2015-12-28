package fetchers

import "github.com/coreos/clair/updater"

// NVDFetcher implements updater.Fetcher and gets vulnerability updates from
// the National Vulnerability Database (NVD), from the
// National Institute of Standards and Technology (NIST).
type NVDFetcher struct{}

func init() {
	//updater.RegisterFetcher("NVD", &RHELFetcher{})
}

// FetchUpdate gets vulnerability updates from the NVD database.
func (f *NVDFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching NVD vulneratibilities")

	return
}
