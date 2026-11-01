//go:build arm64

package core

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var hardwareAEGIS = cpu.ARM64.HasAES || runtime.GOOS == "darwin"

type aegisEngine = libAEGISEngine

func newAEGISEngine(key *[sessionKeySize]byte) aegisEngine {
	return newLibAEGISEngine(key)
}
