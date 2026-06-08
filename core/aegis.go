package core

import (
	"crypto/cipher"
	"crypto/sha256"

	"github.com/ericlagergren/aegis"
)

func aegis128LKey(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:16]
}

func aegis256Key(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:32]
}

func newAEGIS128L(password string) cipher.AEAD {
	a, err := aegis.New(aegis128LKey(password))
	if err != nil {
		panic(err)
	}
	return a
}

func newAEGIS256(password string) cipher.AEAD {
	a, err := aegis.New(aegis256Key(password))
	if err != nil {
		panic(err)
	}
	return a
}

func newConnCipher(password string, sendIV, recvIV []byte) *aeadCipher {
	key := aegis128LKey(password)
	send, err := aegis.New(key)
	if err != nil {
		panic(err)
	}
	recv, err := aegis.New(key)
	if err != nil {
		panic(err)
	}
	return newAEADCipher(send, recv, sendIV, recvIV)
}

func newHandshakeAEAD(password string) cipher.AEAD {
	a, err := aegis.New(aegis128LKey(password))
	if err != nil {
		panic(err)
	}
	return a
}
