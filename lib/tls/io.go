package tls

import (
	"io/ioutil"

	"github.com/extrame/fabric-ca/internal/pkg/util"
)

type ReadWriter interface {
	ReadFile(filename string) ([]byte, error)
	FileExists(name string) bool
}

type AutoGenerator interface {
	AutoGenerateTLSCertificateKey() error
}

var DefaultRW _rw

type _rw struct{}

func (_ *_rw) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (_ *_rw) FileExists(name string) bool {
	return util.FileExists(name)
}
