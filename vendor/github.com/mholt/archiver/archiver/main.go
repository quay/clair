package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mholt/archiver"
)

func main() {
	if len(os.Args) < 3 {
		fatal(usage)
	}

	cmd, filename := os.Args[1], os.Args[2]
	lowerFilename := strings.ToLower(filename)

	for _, ff := range fileFormats {
		if !strings.HasSuffix(lowerFilename, ff.ext) {
			continue
		}
		var err error
		switch cmd {
		case "make":
			if len(os.Args) < 4 {
				fatal(usage)
			}
			err = ff.create(filename, os.Args[3:])
		case "open":
			dest := ""
			if len(os.Args) == 4 {
				dest = os.Args[3]
			} else if len(os.Args) > 4 {
				fatal(usage)
			}
			err = ff.extract(filename, dest)
		default:
			fatal(usage)
		}
		if err != nil {
			fatal(err)
		}
		return
	}

	fatalf("%s: Unsupported file extension", filename)
}

func fatal(v ...interface{}) {
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func fatalf(s string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, s+"\n", v...)
	os.Exit(1)
}

const usage = `Usage: archiver {make|open} <archive file> [files...]
  make
    Create a new archive file. List the files/folders
    to include in the archive; at least one required.
  open
    Extract an archive file. Give only the archive to
    open and the destination folder to extract into.

  Specifying archive format:
    The format of the archive is determined by its
    file extension. Supported extensions:
      .zip
      .tar.gz
      .tgz

  Existing files:
    When creating an archive file that already exists,
    archiver will overwrite the existing file. When
    extracting files, archiver will NOT overwrite files
    that already exist in the destination path; this
    is treated as an error and extraction will abort.`

var fileFormats = []struct {
	ext     string
	create  archiver.CompressFunc
	extract archiver.DecompressFunc
}{
	{ext: ".zip", create: archiver.Zip, extract: archiver.Unzip},
	{ext: ".tar.gz", create: archiver.TarGz, extract: archiver.UntarGz},
	{ext: ".tgz", create: archiver.TarGz, extract: archiver.UntarGz},
}
