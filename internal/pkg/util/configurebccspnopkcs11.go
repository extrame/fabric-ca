//go:build !pkcs11
// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
)

// ConfigureBCCSP configures BCCSP, using
func ConfigureBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string, usememory bool) error {
	var err error
	if optsPtr == nil {
		return errors.New("nil argument not allowed")
	}
	opts := *optsPtr
	if opts == nil {
		opts = &factory.FactoryOpts{}
	}
	if opts.ProviderName == "" {
		opts.ProviderName = "SW"
	}
	if strings.ToUpper(opts.ProviderName) == "SW" {
		if opts.SwOpts == nil {
			opts.SwOpts = &factory.SwOpts{}
		}
		if opts.SwOpts.HashFamily == "" {
			opts.SwOpts.HashFamily = "SHA2"
		}
		if opts.SwOpts.SecLevel == 0 {
			opts.SwOpts.SecLevel = 256
		}
		if !usememory {
			if opts.SwOpts.FileKeystore == nil {
				opts.SwOpts.FileKeystore = &factory.FileKeystoreOpts{}
			}
			// The mspDir overrides the KeyStorePath; otherwise, if not set, set default
			if mspDir != "" {
				opts.SwOpts.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
			} else if opts.SwOpts.FileKeystore.KeyStorePath == "" {
				opts.SwOpts.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
			}
		} else {
			opts.SwOpts.FileKeystore = nil
		}
	}
	err = makeFileNamesAbsolute(opts, homeDir)
	if err != nil {
		return errors.WithMessage(err, "Failed to make BCCSP files absolute")
	}
	log.Debugf("Initializing BCCSP: %+v", opts)
	if opts.SwOpts != nil {
		log.Debugf("Initializing BCCSP with software options %+v", opts.SwOpts)
	}
	*optsPtr = opts
	return nil
}
