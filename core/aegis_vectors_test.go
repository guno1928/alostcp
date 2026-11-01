package core

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type rfc10032Vector struct {
	number int
	valid  bool
	key    string
	nonce  string
	ad     string
	msg    string
	ct     string
	tag128 string
}

var rfc10032AEGIS128LVectors = []rfc10032Vector{
	{1, true, "10010000000000000000000000000000", "10000200000000000000000000000000", "", "00000000000000000000000000000000", "c1c0e58bd913006feba00f4b3cc3594e", "abe0ece80c24868a226a35d16bdae37a"},
	{2, true, "10010000000000000000000000000000", "10000200000000000000000000000000", "", "", "", "c2b879a67def9d74e6c14f708bbcc9b4"},
	{3, true, "10010000000000000000000000000000", "10000200000000000000000000000000", "0001020304050607", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84", "cc6f3372f6aa1bb82388d695c3962d9a"},
	{4, true, "10010000000000000000000000000000", "10000200000000000000000000000000", "0001020304050607", "000102030405060708090a0b0c0d", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7"},
	{5, true, "10010000000000000000000000000000", "10000200000000000000000000000000", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829", "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637", "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10", "7542a745733014f9474417b337399507"},
	{6, false, "10000200000000000000000000000000", "10010000000000000000000000000000", "0001020304050607", "", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7"},
	{7, false, "10010000000000000000000000000000", "10000200000000000000000000000000", "0001020304050607", "", "79d94593d8c2119d7e8fd9b8fc78", "5c04b3dba849b2701effbe32c7f0fab7"},
	{8, false, "10010000000000000000000000000000", "10000200000000000000000000000000", "0001020304050608", "", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7"},
	{9, false, "10010000000000000000000000000000", "10000200000000000000000000000000", "0001020304050607", "", "79d94593d8c2119d7e8fd9b8fc77", "6c04b3dba849b2701effbe32c7f0fab8"},
}

type vectorEngine interface {
	seal(nonce *[nonceSize]byte, dst, plaintext, ad []byte)
	open(nonce *[nonceSize]byte, dst, ciphertext, tag, ad []byte) bool
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorEngines(key *[sessionKeySize]byte) map[string]vectorEngine {
	native := newAEGISEngine(key)
	lib := newLibAEGISEngine(key)
	return map[string]vectorEngine{"native": &native, "lib": &lib}
}

func TestRFC10032AEGIS128LVectors(t *testing.T) {
	checked := 0
	for _, v := range rfc10032AEGIS128LVectors {
		var key [sessionKeySize]byte
		var nonce [nonceSize]byte
		copy(key[:], mustHex(t, v.key))
		copy(nonce[:], mustHex(t, v.nonce))
		ad, msg, ct, tag := mustHex(t, v.ad), mustHex(t, v.msg), mustHex(t, v.ct), mustHex(t, v.tag128)

		for name, engine := range vectorEngines(&key) {
			if v.valid {
				sealed := make([]byte, len(msg)+tagSize)
				engine.seal(&nonce, sealed, msg, ad)
				if !bytes.Equal(sealed, append(append([]byte(nil), ct...), tag...)) {
					t.Fatalf("vector %d %s: seal = %x, want %x%x", v.number, name, sealed, ct, tag)
				}
			}
			out := bytes.Repeat([]byte{0xAA}, len(ct))
			ok := engine.open(&nonce, out, ct, tag, ad)
			switch {
			case v.valid && !ok:
				t.Fatalf("vector %d %s: open rejected a valid vector", v.number, name)
			case v.valid && !bytes.Equal(out, msg):
				t.Fatalf("vector %d %s: open = %x, want %x", v.number, name, out, msg)
			case !v.valid && ok:
				t.Fatalf("vector %d %s: open accepted a must-fail vector", v.number, name)
			case !v.valid && !bytes.Equal(out, make([]byte, len(ct))):
				t.Fatalf("vector %d %s: unverified plaintext left in output: %x", v.number, name, out)
			}
			checked++
		}
	}
	if want := 2 * len(rfc10032AEGIS128LVectors); checked != want || len(rfc10032AEGIS128LVectors) != 9 {
		t.Fatalf("checked %d engine/vector cases over %d vectors, want %d over 9", checked, len(rfc10032AEGIS128LVectors), want)
	}
}
