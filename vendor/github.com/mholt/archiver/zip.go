// Package archiver makes it super easy to create and open .zip and
// .tar.gz files.
package archiver

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Zip creates a .zip file in the location zipPath containing
// the contents of files listed in filePaths. File paths
// can be those of regular files or directories. Regular
// files are stored at the 'root' of the archive, and
// directories are recursively added.
//
// Files with an extension for formats that are already
// compressed will be stored only, not compressed.
func Zip(zipPath string, filePaths []string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("error creating %s: %v", zipPath, err)
	}
	defer out.Close()

	w := zip.NewWriter(out)
	for _, fpath := range filePaths {
		err = zipFile(w, fpath)
		if err != nil {
			w.Close()
			return err
		}
	}

	return w.Close()
}

func zipFile(w *zip.Writer, source string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("%s: stat: %v", source, err)
	}

	var baseDir string
	if sourceInfo.IsDir() {
		baseDir = filepath.Base(source)
	}

	return filepath.Walk(source, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walking to %s: %v", fpath, err)
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("%s: getting header: %v", fpath, err)
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(fpath, source))
		}

		if info.IsDir() {
			header.Name += "/"
			header.Method = zip.Store
		} else {
			ext := strings.ToLower(path.Ext(header.Name))
			if _, ok := CompressedFormats[ext]; ok {
				header.Method = zip.Store
			} else {
				header.Method = zip.Deflate
			}
		}

		writer, err := w.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("%s: making header: %v", fpath, err)
		}

		if info.IsDir() {
			return nil
		}

		if header.Mode().IsRegular() {
			file, err := os.Open(fpath)
			if err != nil {
				return fmt.Errorf("%s: opening: %v", fpath, err)
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			if err != nil {
				return fmt.Errorf("%s: copying contents: %v", fpath, err)
			}
		}

		return nil
	})
}

// Unzip unzips the .zip file at source into destination.
func Unzip(source, destination string) error {
	r, err := zip.OpenReader(source)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, zf := range r.File {
		if err := unzipFile(zf, destination); err != nil {
			return err
		}
	}

	return nil
}

func unzipFile(zf *zip.File, destination string) error {
	if strings.HasSuffix(zf.Name, "/") {
		return mkdir(filepath.Join(destination, zf.Name))
	}

	rc, err := zf.Open()
	if err != nil {
		return fmt.Errorf("%s: open compressed file: %v", zf.Name, err)
	}
	defer rc.Close()

	return writeNewFile(filepath.Join(destination, zf.Name), rc, zf.FileInfo().Mode())
}

func writeNewFile(fpath string, in io.Reader, fm os.FileMode) error {
	err := os.MkdirAll(path.Dir(fpath), 0755)
	if err != nil {
		return fmt.Errorf("%s: making directory for file: %v", fpath, err)
	}

	out, err := os.Create(fpath)
	if err != nil {
		return fmt.Errorf("%s: creating new file: %v", fpath, err)
	}
	defer out.Close()

	err = out.Chmod(fm)
	if err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("%s: changing file mode: %v", fpath, err)
	}

	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("%s: writing file: %v", fpath, err)
	}
	return nil
}

func writeNewSymbolicLink(fpath string, target string) error {
	err := os.MkdirAll(path.Dir(fpath), 0755)
	if err != nil {
		return fmt.Errorf("%s: making directory for file: %v", fpath, err)
	}

	err = os.Symlink(target, fpath)
	if err != nil {
		return fmt.Errorf("%s: making symbolic link for: %v", fpath, err)
	}

	return nil
}

func mkdir(dirPath string) error {
	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		return fmt.Errorf("%s: making directory: %v", dirPath, err)
	}
	return nil
}

// CompressedFormats is a set of lowercased file extensions
// for file formats that are typically already compressed.
// Compressing already-compressed files often results in
// a larger file. This list is not an exhaustive.
var CompressedFormats = map[string]struct{}{
	".7z":   {},
	".avi":  {},
	".bz2":  {},
	".gif":  {},
	".gz":   {},
	".jpeg": {},
	".jpg":  {},
	".lz":   {},
	".lzma": {},
	".mov":  {},
	".mp3":  {},
	".mp4":  {},
	".mpeg": {},
	".mpg":  {},
	".png":  {},
	".rar":  {},
	".xz":   {},
	".zip":  {},
	".zipx": {},
}

type (
	// CompressFunc is a function that makes an archive.
	CompressFunc func(string, []string) error

	// DecompressFunc is a function that extracts an archive.
	DecompressFunc func(string, string) error
)
