package lib

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/hyperledger/fabric/bccsp"

	"github.com/pkg/errors"
)

type MSPProvider interface {
	WriteFile(path string, bytes []byte, mode os.FileMode) error
	ReadFile(string) ([]byte, error)
	FileExists(path string) bool
	SetRoot(dir string)
	MkdirAll(path string, mode os.FileMode) error
	GetFor(root string) MSPProvider
	Delete(root string) error
}

//该MSPProvider是否是自存储私钥
type SelfSkStore interface {
	GetStoredKeys() map[string][]byte
	StoreSk(bccsp.Key)
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

func (f *FileMSPProvider) FileExists(name string) bool {
	if _, err := os.Stat(filepath.Join(f.root, name)); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (f *FileMSPProvider) ReadFile(file string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(f.root, file))
}

func (f *FileMSPProvider) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(filepath.Join(f.root, path), mode)
}

func (f *FileMSPProvider) GetFor(root string) MSPProvider {
	if root == f.root || f.root == "" {
		f.SetRoot(root)
		return f
	}
	var nF FileMSPProvider
	nF.root = root
	return &nF
}

func (f *FileMSPProvider) Delete(root string) error {
	return os.RemoveAll(root)
}

func RegisterMSPProvider(name string, provider MSPProvider) {
	registeredMSPProvider[name] = provider
}

var registeredMSPProvider = make(map[string]MSPProvider)

func init() {
	RegisterMSPProvider("file", &FileMSPProvider{})
}
