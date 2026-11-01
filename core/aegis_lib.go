package core

import (
	"crypto/cipher"

	"github.com/ericlagergren/aegis"
)

const maxRetainedScratch = 64 << 10

type libAEGISEngine struct {
	aead    cipher.AEAD
	scratch []byte
}

func newLibAEGISEngine(key *[sessionKeySize]byte) libAEGISEngine {
	aead, err := aegis.New(key[:])
	if err != nil {
		panic(err)
	}
	return libAEGISEngine{aead: aead}
}

func (e *libAEGISEngine) seal(nonce *[nonceSize]byte, dst, plaintext, ad []byte) {
	if len(dst) != len(plaintext)+tagSize {
		panic("alostcp: invalid seal buffers")
	}
	e.aead.Seal(dst[:0], nonce[:], plaintext, ad)
}

func (e *libAEGISEngine) open(nonce *[nonceSize]byte, dst, ciphertext, tag, ad []byte) bool {
	if len(dst) != len(ciphertext) || len(tag) != tagSize {
		panic("alostcp: invalid open buffers")
	}
	_, err := e.aead.Open(dst[:0], nonce[:], e.sealedMessage(ciphertext, tag), ad)
	if cap(e.scratch) > maxRetainedScratch {
		clear(e.scratch)
		e.scratch = nil
	}
	return err == nil
}

func (e *libAEGISEngine) sealedMessage(ciphertext, tag []byte) []byte {
	n := len(ciphertext)
	if cap(ciphertext) >= n+tagSize && &ciphertext[:n+1][n] == &tag[0] {
		return ciphertext[:n+tagSize]
	}
	e.scratch = append(append(e.scratch[:0], ciphertext...), tag...)
	return e.scratch
}

func (e *libAEGISEngine) wipe() {
	clear(e.scratch)
	e.scratch = nil
	e.aead = nil
}
