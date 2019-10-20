// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package rpcstatus

import "github.com/zeebo/errs"

func SanitizeInternalErr(msg string, err error, internalClasses ...errs.Class) error {
	for _, class := range internalClasses {
		if class.Has(err) {
			return Error(Internal, errs.New(msg).Error())
		}
	}
	return Error(Internal, err.Error())
}
