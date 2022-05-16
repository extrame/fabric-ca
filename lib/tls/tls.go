/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/extrame/fabric-ca/internal/pkg/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	defaultClientAuth = "noclientcert"
)

var clientAuthTypes = map[string]tls.ClientAuthType{
	"noclientcert":               tls.NoClientCert,
	"requestclientcert":          tls.RequestClientCert,
	"requireanyclientcert":       tls.RequireAnyClientCert,
	"verifyclientcertifgiven":    tls.VerifyClientCertIfGiven,
	"requireandverifyclientcert": tls.RequireAndVerifyClientCert,
}

// DefaultCipherSuites is a set of strong TLS cipher suites
var DefaultCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled    bool   `help:"Enable TLS on the listening port"`
	CertFile   string `def:"tls-cert.pem" help:"PEM-encoded TLS certificate file for server's listening port"`
	KeyFile    string `help:"PEM-encoded TLS key for server's listening port"`
	ClientAuth ClientAuth
}

// ClientAuth defines the key material needed to verify client certificates
type ClientAuth struct {
	Type      string   `def:"noclientcert" help:"Policy the server will follow for TLS Client Authentication."`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled   bool     `skip:"true"`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
	Client    KeyCertFiles
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string `help:"PEM-encoded key file when mutual authentication is enabled"`
	CertFile string `help:"PEM-encoded certificate file when mutual authenticate is enabled"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(rw ReadWriter, cfg *ClientTLSConfig, csp bccsp.BCCSP) (*tls.Config, error) {
	var certs []tls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	logrus.Debugf("CA Files: %+v\n", cfg.CertFiles)
	logrus.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	logrus.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)

	if cfg.Client.CertFile != "" {
		err := checkCertDates(rw, cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}
		var certPemBlock []byte
		certPemBlock, err = rw.ReadFile(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}
		clientCert, err := util.LoadX509KeyPairBytes(certPemBlock, cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		logrus.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := x509.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No trusted root certificates for TLS were provided")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := rw.ReadFile(cacert)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read '%s'", cacert)
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, errors.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}

// AbsTLSClient makes TLS client files absolute
func AbsTLSClient(cfg *ClientTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.CertFiles); i++ {
		cfg.CertFiles[i], err = util.MakeFileAbs(cfg.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.Client.CertFile, err = util.MakeFileAbs(cfg.Client.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.Client.KeyFile, err = util.MakeFileAbs(cfg.Client.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

// AbsTLSServer makes TLS client files absolute
func AbsTLSServer(cfg *ServerTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.ClientAuth.CertFiles); i++ {
		cfg.ClientAuth.CertFiles[i], err = util.MakeFileAbs(cfg.ClientAuth.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.CertFile, err = util.MakeFileAbs(cfg.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.KeyFile, err = util.MakeFileAbs(cfg.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

func checkCertDates(rw ReadWriter, certFile string) error {
	logrus.Debug("Check client TLS certificate for valid dates")
	certPEM, err := rw.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

func GetServerTLSConfig(rw ReadWriter, cfg *ServerTLSConfig, csp bccsp.BCCSP) (tlsConfig *tls.Config, err error) {
	var certPemBlock []byte
	var clientAuth tls.ClientAuthType
	var ok bool

	// If key file is specified and it does not exist or its corresponding certificate file does not exist
	// then need to return error and not start the server. The TLS key file is specified when the user
	// wants the server to use custom tls key and cert and don't want server to auto generate its own. So,
	// when the key file is specified, it must exist on the file system
	if cfg.KeyFile != "" {
		if !rw.FileExists(cfg.KeyFile) {
			return nil, fmt.Errorf("File specified by 'tls.keyfile' does not exist: %s", cfg.KeyFile)
		}
		if !rw.FileExists(cfg.CertFile) {
			return nil, fmt.Errorf("File specified by 'tls.certfile' does not exist: %s", cfg.CertFile)
		}
		logrus.Debugf("TLS Certificate: %s, TLS Key: %s", cfg.CertFile, cfg.KeyFile)
	} else if !rw.FileExists(cfg.CertFile) {
		// TLS key file is not specified, generate TLS key and cert if they are not already generated
		if gw, ok := rw.(AutoGenerator); ok {
			err = gw.AutoGenerateTLSCertificateKey()
		} else {
			err = errors.New("not a AutoGenerator")
		}
		if err != nil {
			return nil, fmt.Errorf("Failed to automatically generate TLS certificate and key: %s", err)
		}
	}

	certPemBlock, err = rw.ReadFile(cfg.CertFile)
	if err != nil {
		return
	}
	var cer *tls.Certificate
	cer, err = util.LoadX509KeyPairBytes(certPemBlock, cfg.CertFile, cfg.KeyFile, csp)
	if err != nil {
		return
	}

	if cfg.ClientAuth.Type == "" {
		cfg.ClientAuth.Type = defaultClientAuth
	}

	logrus.Debugf("Client authentication type requested: %s", cfg.ClientAuth.Type)

	authType := strings.ToLower(cfg.ClientAuth.Type)
	if clientAuth, ok = clientAuthTypes[authType]; !ok {
		return nil, errors.New("Invalid client auth type provided")
	}

	var certPool *x509.CertPool
	if authType != defaultClientAuth {
		certPool, err = LoadPEMCertPool(rw, cfg.ClientAuth.CertFiles)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{*cer},
		ClientAuth:   clientAuth,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: DefaultCipherSuites,
	}
	return
}

// LoadPEMCertPool loads a pool of PEM certificates from list of files
func LoadPEMCertPool(rw ReadWriter, certFiles []string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if len(certFiles) > 0 {
		for _, cert := range certFiles {
			logrus.Debugf("Reading cert file: %s", cert)
			pemCerts, err := rw.ReadFile(cert)
			if err != nil {
				return nil, err
			}

			logrus.Debugf("Appending cert %s to pool", cert)
			if !certPool.AppendCertsFromPEM(pemCerts) {
				return nil, errors.New("Failed to load cert pool")
			}
		}
	}

	return certPool, nil
}
