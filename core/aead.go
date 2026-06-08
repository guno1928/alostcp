//go:build amd64

package core

import "github.com/ericlagergren/subtle"

const tagSize = 16

type aeadCipher struct {
	key       [16]byte
	sendNonce [16]byte
	recvNonce [16]byte
}

func newAEADCipherKey(key, sendIV, recvIV []byte) *aeadCipher {
	c := &aeadCipher{}
	copy(c.key[:], key)
	copy(c.sendNonce[:], sendIV)
	copy(c.recvNonce[:], recvIV)
	return c
}

func (c *aeadCipher) seal(dst, plaintext, ad []byte) {
	var z byte
	pp := &z
	if len(plaintext) > 0 {
		pp = &plaintext[0]
	}
	aegisSeal(&c.key[0], &c.sendNonce[0], &dst[0], pp, &ad[0], len(plaintext), len(ad))
	incrementNonce(c.sendNonce[:])
}

func (c *aeadCipher) open(dst, ciphertextWithTag, ad []byte) ([]byte, error) {
	plainLen := len(ciphertextWithTag) - tagSize
	ct := ciphertextWithTag[:plainLen]
	tag := ciphertextWithTag[plainLen:]
	var z byte
	cp := &z
	if plainLen > 0 {
		cp = &ct[0]
	}
	dp := &z
	if cap(dst) > 0 {
		dp = &dst[:1][0]
	}
	var computed [16]byte
	aegisOpen(&c.key[0], &c.recvNonce[0], dp, cp, &ad[0], &computed[0], plainLen, len(ad))
	if subtle.ConstantTimeCompare(computed[:], tag) != 1 {
		return nil, errAEGISOpen
	}
	incrementNonce(c.recvNonce[:])
	return dst[:plainLen], nil
}

func (c *aeadCipher) openInPlace(buf, tag, ad []byte) error {
	var z byte
	bp := &z
	if len(buf) > 0 {
		bp = &buf[0]
	}
	var computed [16]byte
	aegisOpen(&c.key[0], &c.recvNonce[0], bp, bp, &ad[0], &computed[0], len(buf), len(ad))
	if subtle.ConstantTimeCompare(computed[:], tag) != 1 {
		return errAEGISOpen
	}
	incrementNonce(c.recvNonce[:])
	return nil
}

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
