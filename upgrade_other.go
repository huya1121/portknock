//go:build windows

package main

import "os/exec"

// detachProcess is a no-op on non-Unix (used only for local test builds; the
// real service always runs on Linux).
func detachProcess(cmd *exec.Cmd) {}
