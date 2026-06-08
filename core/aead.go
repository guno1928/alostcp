package core

import "crypto/cipher"

const tagSize = 16

type aeadCipher struct {
	send      cipher.AEAD
	recv      cipher.AEAD
	sendNonce []byte
	recvNonce []byte
}

func newAEADCipher(send, recv cipher.AEAD, sendIV, recvIV []byte) *aeadCipher {
	sn := make([]byte, send.NonceSize())
	rn := make([]byte, recv.NonceSize())
	copy(sn, sendIV)
	copy(rn, recvIV)
	return &aeadCipher{
		send:      send,
		recv:      recv,
		sendNonce: sn,
		recvNonce: rn,
	}
}

// seal encrypts plaintext into dst (which must have cap >= len(plaintext)+tagSize),
// authenticates ad, and advances the send nonce.
func (c *aeadCipher) seal(dst, plaintext, ad []byte) {
	c.send.Seal(dst[:0], c.sendNonce, plaintext, ad)
	incrementNonce(c.sendNonce)
}

// open verifies and decrypts ciphertextWithTag into dst, authenticating ad, and
// advances the recv nonce on success.
func (c *aeadCipher) open(dst, ciphertextWithTag, ad []byte) ([]byte, error) {
	plain, err := c.recv.Open(dst[:0], c.recvNonce, ciphertextWithTag, ad)
	if err != nil {
		return nil, err
	}
	incrementNonce(c.recvNonce)
	return plain, nil
}

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
