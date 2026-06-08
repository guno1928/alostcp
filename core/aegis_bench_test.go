package core

import (
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func benchSeal(b *testing.B, mk func() cipher.AEAD) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			aead := mk()
			nonce := make([]byte, aead.NonceSize())
			rand.Read(nonce)
			src := make([]byte, size)
			rand.Read(src)
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
			nonce := make([]byte, aead.NonceSize())
			rand.Read(nonce)
			src := make([]byte, size)
			rand.Read(src)
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

func BenchmarkAEGIS128LLibSeal(b *testing.B) { benchSeal(b, func() cipher.AEAD { return newAEGIS128L("benchmark-password") }) }
func BenchmarkAEGIS128LLibOpen(b *testing.B) { benchOpen(b, func() cipher.AEAD { return newAEGIS128L("benchmark-password") }) }
func BenchmarkAEGIS256LibSeal(b *testing.B)  { benchSeal(b, func() cipher.AEAD { return newAEGIS256("benchmark-password") }) }
func BenchmarkAEGIS256LibOpen(b *testing.B)  { benchOpen(b, func() cipher.AEAD { return newAEGIS256("benchmark-password") }) }
func BenchmarkAEGIS128LAsmSeal(b *testing.B) { benchSeal(b, func() cipher.AEAD { return newAEGIS128LAsm("benchmark-password") }) }
func BenchmarkAEGIS128LAsmOpen(b *testing.B) { benchOpen(b, func() cipher.AEAD { return newAEGIS128LAsm("benchmark-password") }) }
