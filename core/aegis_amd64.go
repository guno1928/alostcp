//go:build amd64

package core

import (
	"crypto/subtle"

	"golang.org/x/sys/cpu"
)

var hardwareAEGIS = cpu.X86.HasAES

//go:noescape
func aegisSeal(key, nonce, dst, src, ad *byte, srcLen, adLen int)

//go:noescape
func aegisOpen(key, nonce, dst, src, ad, tag *byte, srcLen, adLen int)

type aegisEngine struct {
	key [sessionKeySize]byte
}

func newAEGISEngine(key *[sessionKeySize]byte) aegisEngine {
	return aegisEngine{key: *key}
}

func firstByte(b []byte, fallback *byte) *byte {
	if len(b) == 0 {
		return fallback
	}
	return &b[0]
}

func (e *aegisEngine) seal(nonce *[nonceSize]byte, dst, plaintext, ad []byte) {
	if len(dst) != len(plaintext)+tagSize {
		panic("alostcp: invalid seal buffers")
	}
	var empty byte
	aegisSeal(&e.key[0], &nonce[0], &dst[0], firstByte(plaintext, &empty), firstByte(ad, &empty), len(plaintext), len(ad))
}

func (e *aegisEngine) open(nonce *[nonceSize]byte, dst, ciphertext, tag, ad []byte) bool {
	if len(dst) != len(ciphertext) || len(tag) != tagSize {
		panic("alostcp: invalid open buffers")
	}
	var empty byte
	var computed [tagSize]byte
	aegisOpen(&e.key[0], &nonce[0], firstByte(dst, &empty), firstByte(ciphertext, &empty), firstByte(ad, &empty), &computed[0], len(ciphertext), len(ad))
	if subtle.ConstantTimeCompare(computed[:], tag) != 1 {
		clear(dst)
		return false
	}
	return true
}

func (e *aegisEngine) wipe() {
	clear(e.key[:])
}
