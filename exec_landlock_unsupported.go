//go:build !linux

package main

import "fmt"

func applyFilesystemPolicy(config containerConfig) error {
	return fmt.Errorf("Landlock filesystem policy is only supported on Linux")
}
