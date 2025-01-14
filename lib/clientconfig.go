/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package lib

import (
	"fmt"
	"path"
	"strings"

	"github.com/extrame/fabric-ca/internal/pkg/api"
	"github.com/extrame/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// ClientConfig is the fabric-ca client's config
type ClientConfig struct {
	URL        string `def:"http://localhost:7054" opt:"u" help:"URL of fabric-ca-server"`
	MSPDir     string `def:"msp" opt:"M" help:"Membership Service Provider directory"`
	MSPType    string `def:"file" help:"The Msp storage type [file/wallet/inmemory]"`
	TLS        tls.ClientTLSConfig
	Enrollment api.EnrollmentRequest
	CSR        api.CSRInfo
	ID         api.RegistrationRequest
	Revoke     api.RevocationRequest
	CAInfo     api.GetCAInfoRequest
	CAName     string               `help:"Name of CA"`
	CSP        *factory.FactoryOpts `mapstructure:"bccsp" hide:"true"`
	Debug      bool                 `opt:"d" help:"Enable debug level logging" hide:"true"`
	LogLevel   string               `help:"Set logging level (info, warning, debug, error, fatal, critical)"`
	IP         string
}

func (c *ClientConfig) GetMSPProvider(dir ...string) MSPProvider {
	if c.MSPType == "" {
		c.MSPType = "file"
	}
	msp, ok := registeredMSPProvider[c.MSPType]
	if ok {
		if len(dir) > 0 {
			return msp.GetFor(dir[0])
		}
		return msp.GetFor(c.MSPDir)
	}
	return nil
}

func (c *ClientConfig) DeleteMSP(dir ...string) error {
	provider := c.GetMSPProvider(dir...)
	if provider != nil {
		if len(dir) > 0 {
			return provider.Delete(dir[0])
		} else {
			return provider.Delete(c.MSPDir)
		}
	}
	return errors.New("no msp provider")
}

func (c *ClientConfig) GetCustomizedIP() string {
	return c.IP
}

// Enroll a client given the server's URL and the client's home directory.
// The URL may be of the form: http://user:pass@host:port where user and pass
// are the enrollment ID and secret, respectively.
func (c *ClientConfig) Enroll(req *api.EnrollmentRequest, home string, mspDir ...string) (*EnrollmentResponse, error) {
	if req.Name == "" {
		return nil, errors.Errorf(
			"Missing the enrollment ID and secret;"+
				" found '%s' with out user and secret", c.URL)
	}

	client := &Client{HomeDir: home, Config: c}
	if len(mspDir) > 0 {
		client.MSPDir = mspDir[0]
	}
	return client.Enroll(req)
}

func (c *ClientConfig) NewEnrollment() *api.EnrollmentRequest {

	var enrollment = new(api.EnrollmentRequest)
	enrollment.Name = c.Enrollment.Name
	enrollment.Secret = c.Enrollment.Secret
	enrollment.CAName = c.CAName
	var csr api.CSRInfo
	csr = c.CSR
	enrollment.CSR = &csr
	return enrollment
}

// GenCSR generates a certificate signing request and writes the CSR to a file.
func (c *ClientConfig) GenCSR(home string) error {

	client := &Client{HomeDir: home, Config: c}
	// Generate the CSR

	err := client.Init()
	if err != nil {
		return err
	}

	if c.CSR.CN == "" {
		return errors.Errorf("CSR common name not specified; use '--csr.cn' flag")
	}

	csrPEM, _, err := client.GenCSR(&c.CSR, c.CSR.CN)
	if err != nil {
		return err
	}

	csrFile := path.Join("signcerts", fmt.Sprintf("%s.csr", c.CSR.CN))
	err = c.GetMSPProvider().WriteFile(csrFile, csrPEM, 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the CSR")
	}
	log.Infof("Stored CSR at %s", csrFile)
	return nil
}

// ProcessAttributeStrings parses attribute requests from strings
// Each string is of the form: <attrName>[:opt] where "opt" means the attribute is
// optional and will not return an error if the identity does not possess the attribute.
// The default is that each attribute name listed is required and so the identity must
// possess the attribute.
func (cfg *ClientConfig) ProcessAttributeStrings(cfgAttrReqs []string) error {
	if len(cfgAttrReqs) == 0 {
		return nil
	}
	reqs := make([]*api.AttributeRequest, len(cfgAttrReqs))
	for idx, req := range cfgAttrReqs {
		sreq := strings.Split(req, ":")
		name := sreq[0]
		switch len(sreq) {
		case 1:
			reqs[idx] = &api.AttributeRequest{Name: name}
		case 2:
			if sreq[1] != "opt" {
				return errors.Errorf("Invalid option in attribute request specification at '%s'; the value after the colon must be 'opt'", req)
			}
			reqs[idx] = &api.AttributeRequest{Name: name, Optional: true}
		default:
			return errors.Errorf("Multiple ':' characters not allowed in attribute request specification; error at '%s'", req)
		}
	}
	cfg.Enrollment.AttrReqs = reqs
	return nil
}

// Register registers a new identity
// @param req The registration request
func (c *ClientConfig) Register(home string, mspDir ...string) (rr *RegistrationResponse, err error) {

	client := &Client{HomeDir: home, Config: c}
	if len(mspDir) > 0 {
		client.MSPDir = mspDir[0]
	}
	client.HomeDir = home

	id, err := client.LoadMyIdentity()
	if err != nil {
		return nil, err
	}

	c.ID.CAName = c.CAName
	resp, err := id.Register(&c.ID)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Password: %s\n", resp.Secret)

	return resp, nil
}

type ModifyIdentityRequest struct {
	api.ModifyIdentityRequest
}

func (c *ClientConfig) ModifyIdentity(home string, request *ModifyIdentityRequest) error {

	client := &Client{HomeDir: home, Config: c}
	client.HomeDir = home

	req := &api.ModifyIdentityRequest{}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req = &request.ModifyIdentityRequest
	req.Attributes = c.ID.Attributes

	req.CAName = c.CAName
	resp, err := id.ModifyIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Secret: %s, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Secret, resp.Attributes)
	return nil
}
