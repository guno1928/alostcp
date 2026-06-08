//go:build amd64

package core

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"github.com/ericlagergren/subtle"
)

var errAEGISOpen = errors.New("alostcp: message authentication failed")

type asmAEGIS128L struct {
	key [16]byte
}

func newAEGIS128LAsm(password string) cipher.AEAD {
	sum := sha256.Sum256([]byte(password))
	a := &asmAEGIS128L{}
	copy(a.key[:], sum[:16])
	return a
}

func (a *asmAEGIS128L) NonceSize() int { return 16 }
func (a *asmAEGIS128L) Overhead() int  { return 16 }

//go:noescape
func aegisSeal(key, nonce, dst, src, ad *byte, srcLen, adLen int)

//go:noescape
func aegisOpen(key, nonce, dst, src, ad, tag *byte, srcLen, adLen int)

func (a *asmAEGIS128L) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 16 {
		panic("alostcp: invalid AEGIS nonce size")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+16)
	var z byte
	sp := &z
	if len(plaintext) > 0 {
		sp = &plaintext[0]
	}
	ap := &z
	if len(additionalData) > 0 {
		ap = &additionalData[0]
	}
	aegisSeal(&a.key[0], &nonce[0], &out[0], sp, ap, len(plaintext), len(additionalData))
	return ret
}

func (a *asmAEGIS128L) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 16 {
		panic("alostcp: invalid AEGIS nonce size")
	}
	if len(ciphertext) < 16 {
		return nil, errAEGISOpen
	}
	tagOffset := len(ciphertext) - 16
	ct := ciphertext[:tagOffset]
	recvTag := ciphertext[tagOffset:]

	ret, out := sliceForAppend(dst, len(ct))
	var z byte
	sp := &z
	if len(ct) > 0 {
		sp = &ct[0]
	}
	ap := &z
	if len(additionalData) > 0 {
		ap = &additionalData[0]
	}
	op := &z
	if len(out) > 0 {
		op = &out[0]
	}
	var computed [16]byte
	aegisOpen(&a.key[0], &nonce[0], op, sp, ap, &computed[0], len(ct), len(additionalData))
	if subtle.ConstantTimeCompare(computed[:], recvTag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errAEGISOpen
	}
	return ret, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
