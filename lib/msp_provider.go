package lib

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
)

type MSPProvider interface {
	WriteFile(path string, bytes []byte, mode os.FileMode) error
	SetRoot(dir string)
}

type FileMSPProvider struct {
	root string
}

func (f *FileMSPProvider) SetRoot(dir string) {
	f.root = dir
}

// WriteFile writes a file
func (f *FileMSPProvider) WriteFile(file string, buf []byte, perm os.FileMode) error {
	file = filepath.Join(f.root, file)
	dir := path.Dir(file)
	// Create the directory if it doesn't exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrapf(err, "Failed to create directory '%s' for file '%s'", dir, file)
		}
	}
	return ioutil.WriteFile(file, buf, perm)
}

func RegisterMSPProvider(name string, provider MSPProvider) {
	registeredMSPProvider[name] = provider
}

var registeredMSPProvider = make(map[string]MSPProvider)

func init() {
	RegisterMSPProvider("file", &FileMSPProvider{})
}
