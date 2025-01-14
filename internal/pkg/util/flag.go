/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	logging "github.com/op/go-logging"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// TagDefault is the tag name for a default value of a field as recognized
	// by RegisterFlags.
	TagDefault = "def"
	// TagHelp is the tag name for a help message of a field as recognized
	// by RegisterFlags.
	TagHelp = "help"
	// TagOpt is the tag name for a one character option of a field as recognized
	// by RegisterFlags.  For example, a value of "d" reserves "-d" for the
	// command line argument.
	TagOpt = "opt"
	// TagSkip is the tag name which causes the field to be skipped by
	// RegisterFlags.
	TagSkip = "skip"
	// TagHide is the tag name which causes the field to be hidden
	TagHide = "hide"
)

// RegisterFlags registers flags for all fields in an arbitrary 'config' object.
// This method recognizes the following field tags:
// "def" - the default value of the field;
// "opt" - the optional one character short name to use on the command line;
// "help" - the help message to display on the command line;
// "skip" - to skip the field.
func RegisterFlags(v *viper.Viper, flags *pflag.FlagSet, config interface{},
	tags map[string]string) error {
	fr := &flagRegistrar{flags: flags, tags: tags, viper: v}
	return ParseObj(config, fr.Register, tags)
}

type flagRegistrar struct {
	flags *pflag.FlagSet
	tags  map[string]string
	viper *viper.Viper
}

func (fr *flagRegistrar) Register(f *Field) (err error) {
	// Don't register non-leaf fields
	if !f.Leaf {
		return nil
	}
	// Don't register fields with no address
	if f.Addr == nil {
		return errors.Errorf("Field is not addressable: %s", f.Path)
	}
	skip := fr.getTag(f, TagSkip)
	if skip != "" {
		return nil
	}

	help := fr.getTag(f, TagHelp)
	opt := fr.getTag(f, TagOpt)
	def := fr.getTag(f, TagDefault)
	hide := fr.getHideBooleanTag(f)
	switch f.Kind {

	case reflect.String:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		fr.flags.StringVarP(f.Addr.(*string), f.Path, opt, def, help)
	case reflect.Int:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		var intDef int
		if def != "" {
			intDef, err = strconv.Atoi(def)
			if err != nil {
				return errors.Errorf("Invalid integer value in 'def' tag of %s field", f.Path)
			}
		}
		fr.flags.IntVarP(f.Addr.(*int), f.Path, opt, intDef, help)
	case reflect.Int64:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		d, ok := f.Addr.(*time.Duration)
		if !ok {
			var intDef int64
			if def != "" {
				intDef, err = strconv.ParseInt(def, 10, 64)
				if err != nil {
					return errors.Errorf("Invalid int64 value in 'def' tag of %s field", f.Path)
				}
			}
			fr.flags.Int64VarP(f.Addr.(*int64), f.Path, opt, intDef, help)
		} else {
			var intDef time.Duration
			if def != "" {
				intDef, err = time.ParseDuration(def)
				if err != nil {
					return errors.Errorf("Invalid duration value in 'def' tag of %s field", f.Path)
				}
			}
			fr.flags.DurationVarP(d, f.Path, opt, intDef, help)
		}
	case reflect.Bool:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		var boolDef bool
		if def != "" {
			boolDef, err = strconv.ParseBool(def)
			if err != nil {
				return errors.Errorf("Invalid boolean value in 'def' tag of %s field", f.Path)
			}
		}
		fr.flags.BoolVarP(f.Addr.(*bool), f.Path, opt, boolDef, help)
	case reflect.Slice:
		if f.Type.Elem().Kind() == reflect.String {
			if help == "" && !hide {
				return errors.Errorf("Field is missing a help tag: %s", f.Path)
			}
			fr.flags.StringSliceVarP(f.Addr.(*[]string), f.Path, opt, nil, help)
		} else {
			return nil
		}
	default:
		log.Debugf("Not registering flag for '%s' because it is a currently unsupported type: %s\n",
			f.Path, f.Kind)
		return nil
	}
	if hide {
		fr.flags.MarkHidden(f.Path)
	}
	bindFlag(fr.viper, fr.flags, f.Path)
	return nil
}

func (fr *flagRegistrar) getTag(f *Field, tagName string) string {
	var key, val string
	key = fmt.Sprintf("%s.%s", tagName, f.Path)
	if fr.tags != nil {
		val = fr.tags[key]
	}
	if val == "" {
		val = f.Tag.Get(tagName)
	}
	return val
}

func (fr *flagRegistrar) getHideBooleanTag(f *Field) bool {
	boolVal, err := strconv.ParseBool(f.Hide)
	if err != nil {
		return false
	}
	return boolVal
}

// CmdRunBegin is called at the beginning of each cobra run function
func CmdRunBegin(v *viper.Viper) {
	// If -d or --debug, set debug logging level
	if v.GetBool("debug") {
		log.Level = log.LevelDebug

		logging.SetLevel(logging.INFO, "bccsp")
		logging.SetLevel(logging.INFO, "bccsp_p11")
		logging.SetLevel(logging.INFO, "bccsp_sw")
	}
}

// FlagString sets up a flag for a string, binding it to its name
func FlagString(v *viper.Viper, flags *pflag.FlagSet, name, short string, def string, desc string) {
	flags.StringP(name, short, def, desc)
	bindFlag(v, flags, name)
}

// common binding function
func bindFlag(v *viper.Viper, flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(fmt.Errorf("failed to lookup '%s'", name))
	}
	v.BindPFlag(name, flag)
}
