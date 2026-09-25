//go:build !windows || (!amd64 && !arm64)

package main

import "errors"

func runPlatform(config) error {
	return errors.New("tunneldemo requires Windows amd64 or arm64")
}
