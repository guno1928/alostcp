//go:build amd64

package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/ericlagergren/aegis"
)

type asmAEAD struct {
	engine aegisEngine
}

func newAsmAEAD(key []byte) *asmAEAD {
	var k [sessionKeySize]byte
	copy(k[:], key)
	return &asmAEAD{engine: newAEGISEngine(&k)}
}

func (a *asmAEAD) NonceSize() int { return nonceSize }
func (a *asmAEAD) Overhead() int  { return tagSize }

func (a *asmAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	n := len(dst)
	ret := slices.Grow(dst, len(plaintext)+tagSize)[:n+len(plaintext)+tagSize]
	a.engine.seal((*[nonceSize]byte)(nonce), ret[n:], plaintext, ad)
	return ret
}

func (a *asmAEAD) Open(dst, nonce, sealed, ad []byte) ([]byte, error) {
	if len(sealed) < tagSize {
		return nil, errAuthFailed
	}
	ctLen := len(sealed) - tagSize
	n := len(dst)
	ret := slices.Grow(dst, ctLen)[:n+ctLen]
	if !a.engine.open((*[nonceSize]byte)(nonce), ret[n:], sealed[:ctLen], sealed[ctLen:], ad) {
		return nil, errAuthFailed
	}
	return ret, nil
}

var _ cipher.AEAD = (*asmAEAD)(nil)

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAEGIS128LAsmMatchesLibrary(t *testing.T) {
	key := randomBytes(t, sessionKeySize)
	nonce := randomBytes(t, nonceSize)
	ref, err := aegis.New(key)
	if err != nil {
		t.Fatal(err)
	}
	asm := newAsmAEAD(key)

	sizes := []int{0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 255, 256, 1000, 4096, 65536}
	adSizes := []int{0, 1, 4, 15, 16, 17, 32, 33, 64}
	for _, sz := range sizes {
		for _, adSz := range adSizes {
			pt := randomBytes(t, sz)
			ad := randomBytes(t, adSz)

			want := ref.Seal(nil, nonce, pt, ad)
			got := asm.Seal(nil, nonce, pt, ad)
			if !bytes.Equal(want, got) {
				t.Fatalf("Seal mismatch sz=%d adSz=%d", sz, adSz)
			}
			opened, err := asm.Open(nil, nonce, want, ad)
			if err != nil || !bytes.Equal(opened, pt) {
				t.Fatalf("asm Open of library output failed sz=%d adSz=%d: %v", sz, adSz, err)
			}
			refOpened, err := ref.Open(nil, nonce, got, ad)
			if err != nil || !bytes.Equal(refOpened, pt) {
				t.Fatalf("library Open of asm output failed sz=%d adSz=%d: %v", sz, adSz, err)
			}
			inPlace := append([]byte(nil), got...)
			opened, err = asm.Open(inPlace[:0], nonce, inPlace, ad)
			if err != nil || !bytes.Equal(opened, pt) {
				t.Fatalf("in-place Open failed sz=%d adSz=%d: %v", sz, adSz, err)
			}
		}
	}
}

func TestAEGIS128LAsmTamperDetection(t *testing.T) {
	asm := newAsmAEAD(randomBytes(t, sessionKeySize))
	nonce := randomBytes(t, nonceSize)
	pt := randomBytes(t, 200)
	ad := []byte{0, 0, 0, 200}
	ct := asm.Seal(nil, nonce, pt, ad)

	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := asm.Open(nil, nonce, bad, ad); err == nil {
			t.Fatalf("tampered byte %d was accepted", i)
		}
	}
	if _, err := asm.Open(nil, nonce, ct, []byte{0, 0, 0, 201}); err == nil {
		t.Fatal("tampered AD was accepted")
	}
}

func TestAEGIS128LAsmRandomDifferential(t *testing.T) {
	for iter := 0; iter < 2000; iter++ {
		key := randomBytes(t, sessionKeySize)
		nonce := randomBytes(t, nonceSize)
		ref, err := aegis.New(key)
		if err != nil {
			t.Fatal(err)
		}
		asm := newAsmAEAD(key)

		sizes := randomBytes(t, 2)
		sz := (int(sizes[0]) | int(sizes[1])<<8) % 5000
		adSz := int(sizes[0]) % 70
		pt := randomBytes(t, sz)
		ad := randomBytes(t, adSz)

		want := ref.Seal(nil, nonce, pt, ad)
		got := asm.Seal(nil, nonce, pt, ad)
		if !bytes.Equal(want, got) {
			t.Fatalf("iter %d: Seal mismatch sz=%d adSz=%d", iter, sz, adSz)
		}
		opened, err := asm.Open(nil, nonce, want, ad)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Fatalf("iter %d: Open mismatch sz=%d adSz=%d: %v", iter, sz, adSz, err)
		}
	}
}

func TestEnginesClearOutputOnAuthFailure(t *testing.T) {
	var key [sessionKeySize]byte
	copy(key[:], randomBytes(t, sessionKeySize))
	var nonce [nonceSize]byte
	ad := []byte{1, 2, 3, 4}
	pt := bytes.Repeat([]byte("transfer=0000100;"), 5)

	asm := newAEGISEngine(&key)
	lib := newLibAEGISEngine(&key)
	sealed := make([]byte, len(pt)+tagSize)
	asm.seal(&nonce, sealed, pt, ad)
	sealed[3] ^= 0x40

	for name, open := range map[string]func(dst, ct, tag []byte) bool{
		"asm": func(dst, ct, tag []byte) bool { return asm.open(&nonce, dst, ct, tag, ad) },
		"lib": func(dst, ct, tag []byte) bool { return lib.open(&nonce, dst, ct, tag, ad) },
	} {
		out := make([]byte, len(pt))
		if open(out, sealed[:len(pt)], sealed[len(pt):]) {
			t.Fatalf("%s: tampered ciphertext accepted", name)
		}
		if !bytes.Equal(out, make([]byte, len(pt))) {
			t.Fatalf("%s: unverified plaintext left in output: %q", name, out)
		}
	}
}

func TestLibEngineMatchesAsmEngine(t *testing.T) {
	var key [sessionKeySize]byte
	copy(key[:], randomBytes(t, sessionKeySize))
	ad := []byte{0, 0, 0, 9}
	for _, sz := range []int{0, 1, 31, 32, 33, 100, 4096} {
		var nonce [nonceSize]byte
		copy(nonce[:], randomBytes(t, nonceSize))
		asm := newAEGISEngine(&key)
		lib := newLibAEGISEngine(&key)
		pt := randomBytes(t, sz)

		fromAsm := make([]byte, sz+tagSize)
		fromLib := make([]byte, sz+tagSize)
		asm.seal(&nonce, fromAsm, pt, ad)
		lib.seal(&nonce, fromLib, pt, ad)
		if !bytes.Equal(fromAsm, fromLib) {
			t.Fatalf("size %d: lib seal differs from asm seal", sz)
		}

		contiguous := make([]byte, sz)
		if !lib.open(&nonce, contiguous, fromAsm[:sz], fromAsm[sz:], ad) || !bytes.Equal(contiguous, pt) {
			t.Fatalf("size %d: lib open with contiguous tag failed", sz)
		}
		split := append([]byte(nil), fromAsm[:sz]...)
		tag := append([]byte(nil), fromAsm[sz:]...)
		if !lib.open(&nonce, split, split, tag, ad) || !bytes.Equal(split, pt) {
			t.Fatalf("size %d: lib in-place open with separate tag failed", sz)
		}

		lib.wipe()
		if lib.aead != nil || lib.scratch != nil {
			t.Fatalf("size %d: lib engine kept key state after wipe", sz)
		}
	}
}
