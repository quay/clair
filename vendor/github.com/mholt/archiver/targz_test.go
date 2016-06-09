package archiver

import "testing"

func TestTarGzAndUntarGz(t *testing.T) {
	symmetricTest(t, ".tar.gz", TarGz, UntarGz)
}
