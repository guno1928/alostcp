//go:build amd64

package core

import (
	"crypto/cipher"
	"testing"

	"github.com/ericlagergren/aegis"
)

func benchmarkKey(size int) []byte {
	key := make([]byte, size)
	copy(key, "benchmark-password-key-material!")
	return key
}

func newLibAEAD(b *testing.B, keySize int) cipher.AEAD {
	a, err := aegis.New(benchmarkKey(keySize))
	if err != nil {
		b.Fatal(err)
	}
	return a
}

func benchSeal(b *testing.B, mk func() cipher.AEAD) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			aead := mk()
			nonce := randomBytes(b, aead.NonceSize())
			src := randomBytes(b, size)
			ad := []byte{0, 0, 0, 0}
			dst := make([]byte, 0, size+tagSize)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = aead.Seal(dst[:0], nonce, src, ad)
			}
		})
	}
}

func benchOpen(b *testing.B, mk func() cipher.AEAD) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			aead := mk()
			nonce := randomBytes(b, aead.NonceSize())
			src := randomBytes(b, size)
			ad := []byte{0, 0, 0, 0}
			ct := aead.Seal(nil, nonce, src, ad)
			dst := make([]byte, 0, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := aead.Open(dst[:0], nonce, ct, ad); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAEGIS128LLibSeal(b *testing.B) {
	benchSeal(b, func() cipher.AEAD { return newLibAEAD(b, 16) })
}

func BenchmarkAEGIS128LLibOpen(b *testing.B) {
	benchOpen(b, func() cipher.AEAD { return newLibAEAD(b, 16) })
}

func BenchmarkAEGIS256LibSeal(b *testing.B) {
	benchSeal(b, func() cipher.AEAD { return newLibAEAD(b, 32) })
}

func BenchmarkAEGIS256LibOpen(b *testing.B) {
	benchOpen(b, func() cipher.AEAD { return newLibAEAD(b, 32) })
}

func BenchmarkAEGIS128LAsmSeal(b *testing.B) {
	benchSeal(b, func() cipher.AEAD { return newAsmAEAD(benchmarkKey(16)) })
}

func BenchmarkAEGIS128LAsmOpen(b *testing.B) {
	benchOpen(b, func() cipher.AEAD { return newAsmAEAD(benchmarkKey(16)) })
}
