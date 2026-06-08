package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ericlagergren/aegis"
)

func TestAEGIS128LAsmMatchesLibrary(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)

	ref, err := aegis.New(key)
	if err != nil {
		t.Fatal(err)
	}
	asm := &asmAEGIS128L{}
	copy(asm.key[:], key)

	sizes := []int{0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 255, 256, 1000, 4096, 65536}
	adSizes := []int{0, 1, 4, 15, 16, 17, 32, 33, 64}

	for _, sz := range sizes {
		for _, adSz := range adSizes {
			pt := make([]byte, sz)
			ad := make([]byte, adSz)
			rand.Read(pt)
			rand.Read(ad)

			want := ref.Seal(nil, nonce, pt, ad)
			got := asm.Seal(nil, nonce, pt, ad)
			if !bytes.Equal(want, got) {
				t.Fatalf("Seal mismatch sz=%d adSz=%d\n want=%x\n  got=%x", sz, adSz, want, got)
			}

			opened, err := asm.Open(nil, nonce, got, ad)
			if err != nil {
				t.Fatalf("Open failed sz=%d adSz=%d: %v", sz, adSz, err)
			}
			if !bytes.Equal(opened, pt) {
				t.Fatalf("Open roundtrip mismatch sz=%d adSz=%d", sz, adSz)
			}
		}
	}
}

func TestAEGIS128LAsmTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)
	asm := &asmAEGIS128L{}
	copy(asm.key[:], key)

	pt := make([]byte, 200)
	ad := []byte{0, 0, 0, 200}
	rand.Read(pt)
	ct := asm.Seal(nil, nonce, pt, ad)

	for i := 0; i < len(ct); i++ {
		bad := make([]byte, len(ct))
		copy(bad, ct)
		bad[i] ^= 0x01
		if _, err := asm.Open(nil, nonce, bad, ad); err == nil {
			t.Fatalf("tampered byte %d was accepted", i)
		}
	}

	badAD := []byte{0, 0, 0, 201}
	if _, err := asm.Open(nil, nonce, ct, badAD); err == nil {
		t.Fatal("tampered AD was accepted")
	}
}

func TestAEGIS128LAsmRandomDifferential(t *testing.T) {
	for iter := 0; iter < 2000; iter++ {
		key := make([]byte, 16)
		nonce := make([]byte, 16)
		rand.Read(key)
		rand.Read(nonce)
		ref, _ := aegis.New(key)
		asm := &asmAEGIS128L{}
		copy(asm.key[:], key)

		var szb [2]byte
		rand.Read(szb[:])
		sz := int(szb[0]) | int(szb[1])<<8
		sz %= 5000
		adSz := int(szb[0]) % 70

		pt := make([]byte, sz)
		ad := make([]byte, adSz)
		rand.Read(pt)
		rand.Read(ad)

		want := ref.Seal(nil, nonce, pt, ad)
		got := asm.Seal(nil, nonce, pt, ad)
		if !bytes.Equal(want, got) {
			t.Fatalf("iter %d: Seal mismatch sz=%d adSz=%d", iter, sz, adSz)
		}
	}
}
