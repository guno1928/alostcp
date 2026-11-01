//go:build !amd64 && !arm64

package core

var hardwareAEGIS = false

type aegisEngine = libAEGISEngine

func newAEGISEngine(key *[sessionKeySize]byte) aegisEngine {
	return newLibAEGISEngine(key)
}
