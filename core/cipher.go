package core

import (
	"crypto/cipher"
	"crypto/sha256"
)

type Cipher struct {
	sendStream cipher.Stream
	recvStream cipher.Stream
}

func newCipher(password string, sendIV, recvIV []byte) *Cipher {
	sum := sha256.Sum256([]byte(password))
	key := sum[:16]

	sendStream, err := newAESCTRAsm8B(key, sendIV, 10)
	if err != nil {
		panic(err)
	}
	recvStream, err := newAESCTRAsm8B(key, recvIV, 10)
	if err != nil {
		panic(err)
	}
	return &Cipher{
		sendStream: sendStream,
		recvStream: recvStream,
	}
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.sendStream.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.recvStream.XORKeyStream(dst, src)
}

func newHandshakeCipher(password string, iv []byte) cipher.Stream {
	sum := sha256.Sum256([]byte(password))
	key := sum[:16]
	stream, err := newAESCTRAsm8B(key, iv, 10)
	if err != nil {
		panic(err)
	}
	return stream
}
