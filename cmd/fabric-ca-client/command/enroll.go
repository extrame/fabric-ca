/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/extrame/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type enrollCmd struct {
	Command
	IP string
}

func newEnrollCmd(c Command) *enrollCmd {
	enrollCmd := &enrollCmd{c, ""}
	return enrollCmd
}

func (c *enrollCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "enroll -u http://user:userpw@serverAddr:serverPort",
		Short:   "Enroll an identity",
		Long:    "Enroll identity with Fabric CA server",
		PreRunE: c.preRunEnroll,
		RunE:    c.runEnroll,
	}
	return cmd
}

func (c *enrollCmd) preRunEnroll(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runEnroll")
	cfgFileName := c.GetCfgFileName()
	cfg := c.GetClientCfg()
	var resp *lib.EnrollmentResponse
	var err error
	if c.IP != "" {
		dialer := &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
			// DualStack: true, // this is deprecated as of go 1.16
		}
		tr := new(http.Transport)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, c.IP)
		}
		resp, err = cfg.Enroll(cfg.URL, filepath.Dir(cfgFileName), tr)
	} else {
		resp, err = cfg.Enroll(cfg.URL, filepath.Dir(cfgFileName))
	}
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file at '%s'", cfgFileName)
	}

	cfgStr := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfgStr), 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write file at '%s'", cfgFileName)
	}

	err = ID.Store()
	if err != nil {
		return errors.WithMessage(err, "Failed to store enrollment information")
	}

	// Store issuer public key
	err = storeCAChain(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	err = storeIssuerPublicKey(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	return storeIssuerRevocationPublicKey(cfg, &resp.CAInfo)
}

//Enroll call enroll function as a library
//url the server url
//home the home directory
//caname the caname
//ip the ip of server(difference with original library)
func Enroll(url, home, mspdir, pem, caname, ip string) error {
	log.Debug("Entered runEnroll")
	var myViper = viper.New()
	myViper.Set("url", url)
	myViper.Set("tls.certfiles", pem)
	myViper.Set("caname", caname)
	if mspdir != "" {
		myViper.Set("mspdir", mspdir)
	}
	clientCmd := &ClientCmd{
		myViper: myViper,
	}
	clientCmd.name = "enroll"
	clientCmd.homeDirectory = home
	clientCmd.clientCfg = &lib.ClientConfig{}
	err := clientCmd.ConfigInit()
	c := &enrollCmd{clientCmd, ip}
	if err == nil {
		err = c.preRunEnroll(nil, []string{})
		if err == nil {
			return c.runEnroll(nil, []string{})
		}
	}
	return err
}
