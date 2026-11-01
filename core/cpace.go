package core

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/gtank/ristretto255"
)

const (
	cpaceDSI         = "CPaceRistretto255"
	cpaceDSIISK      = cpaceDSI + "_ISK"
	cpacePointSize   = 32
	cpaceSIDSize     = 16
	cpaceUniformSize = 64
	cpaceISKSize     = sha512.Size
)

var errCPaceIdentity = errors.New("alostcp: CPace produced the identity element")

func lebLen(n int) int {
	size := 1
	for n >= 0x80 {
		n >>= 7
		size++
	}
	return size
}

func appendPrependLen(dst, data []byte) []byte {
	n := len(data)
	for n >= 0x80 {
		dst = append(dst, byte(n)|0x80)
		n >>= 7
	}
	dst = append(dst, byte(n))
	return append(dst, data...)
}

func lvCat(parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += lebLen(len(p)) + len(p)
	}
	out := make([]byte, 0, size)
	for _, p := range parts {
		out = appendPrependLen(out, p)
	}
	return out
}

func cpaceGeneratorString(prs, ci, sid []byte) []byte {
	used := lebLen(len(prs)) + len(prs) + lebLen(len(cpaceDSI)) + len(cpaceDSI)
	zpad := max(0, sha512.BlockSize-1-used)
	return lvCat([]byte(cpaceDSI), prs, make([]byte, zpad), ci, sid)
}

func cpaceGenerator(prs, ci, sid []byte) (*ristretto255.Element, error) {
	genStr := cpaceGeneratorString(prs, ci, sid)
	digest := sha512.Sum512(genStr)
	clear(genStr)
	defer clear(digest[:])
	return ristretto255.NewIdentityElement().SetUniformBytes(digest[:])
}

func cpaceSampleScalar() (*ristretto255.Scalar, error) {
	var uniform [cpaceUniformSize]byte
	defer clear(uniform[:])
	zero := ristretto255.NewScalar()
	for {
		if _, err := rand.Read(uniform[:]); err != nil {
			return nil, err
		}
		y, err := ristretto255.NewScalar().SetUniformBytes(uniform[:])
		if err != nil {
			return nil, err
		}
		if y.Equal(zero) == 0 {
			return y, nil
		}
	}
}

func cpacePublicPoint(y *ristretto255.Scalar, g *ristretto255.Element) []byte {
	return ristretto255.NewIdentityElement().ScalarMult(y, g).Bytes()
}

func cpaceSharedPoint(y *ristretto255.Scalar, peerEncoded []byte) ([]byte, error) {
	peer, err := ristretto255.NewIdentityElement().SetCanonicalBytes(peerEncoded)
	if err != nil {
		return nil, err
	}
	shared := ristretto255.NewIdentityElement().ScalarMult(y, peer)
	defer shared.Set(ristretto255.NewIdentityElement())
	if shared.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errCPaceIdentity
	}
	return shared.Bytes(), nil
}

func cpaceISK(sid, sharedPoint, ya, ada, yb, adb []byte) [cpaceISKSize]byte {
	prefix := lvCat([]byte(cpaceDSIISK), sid, sharedPoint)
	transcript := append(lvCat(ya, ada), lvCat(yb, adb)...)
	h := sha512.New()
	h.Write(prefix)
	h.Write(transcript)
	var isk [cpaceISKSize]byte
	h.Sum(isk[:0])
	clear(prefix)
	return isk
}
