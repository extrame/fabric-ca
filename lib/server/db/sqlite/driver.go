//go:build !caclient
// +build !caclient

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite

import (
	_ "modernc.org/sqlite" // import to support SQLite3
)
