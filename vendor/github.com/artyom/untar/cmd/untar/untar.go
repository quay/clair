package untar

import (
	"compress/bzip2"
	"compress/gzip"
	"flag"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/artyom/untar"
)

func main() {
	var (
		dst      = "."
		filename string
	)
	flag.StringVar(&dst, "to", dst, "directory to unpack to")
	flag.StringVar(&filename, "from", filename, "file to extract")
	flag.Parse()
	if dst == "" {
		dst = "."
	}
	if filename == "" {
		flag.Usage()
		os.Exit(1)
	}
	if err := openAndUntar(filename, dst); err != nil {
		log.Fatal(err)
	}
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
