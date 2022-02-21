package tls

import "io/ioutil"

type ReadWriter interface {
	ReadFile(filename string) ([]byte, error)
}

var DefaultRW _rw

type _rw struct{}

func (_ *_rw) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
