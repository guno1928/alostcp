package core

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
)

var cpaceDraft21Vectors = map[string]string{
	"prependEmpty":    "00",
	"prepend1234":     "0431323334",
	"prepend127":      "7f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e",
	"prepend128":      "8001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
	"lvCat":           "043132333401350003363738",
	"transcriptIR1":   "03313233065061727479410332333406506172747942",
	"transcriptIR2":   "043334353606506172747941043233343506506172747942",
	"generatorString": "11435061636552697374726574746f3235350850617373776f72646400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57",
	"generatorHash":   "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af06bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27",
	"generator":       "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
	"ya":              "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08",
	"Ya":              "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157",
	"yb":              "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d",
	"Yb":              "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258",
	"K":               "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f",
	"K2":              "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f",
	"transcriptIR":    "20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462",
	"iskInput":        "15435061636552697374726574746f3235355f49534b107e4b4791d6a8ef019b936c79fb7f2c572080b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462",
	"ISK":             "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447",
	"validS":          "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05",
	"validX":          "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c",
	"validSX":         "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e",
	"invalidY1":       "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c",
	"invalidY2":       "0000000000000000000000000000000000000000000000000000000000000000",
}

func cpaceVector(t *testing.T, name string) []byte {
	t.Helper()
	v, ok := cpaceDraft21Vectors[name]
	if !ok {
		t.Fatalf("missing CPace vector %q", name)
	}
	return mustHex(t, v)
}

func byteRange(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func cpaceTestScalar(t *testing.T, name string) *ristretto255.Scalar {
	t.Helper()
	s, err := ristretto255.NewScalar().SetCanonicalBytes(cpaceVector(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	cpaceTestPRS = []byte("Password")
	cpaceTestCI  = []byte("\x0bA_initiator\x0bB_responder")
	cpaceTestSID = []byte{0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57}
	cpaceTestADa = []byte("ADa")
	cpaceTestADb = []byte("ADb")
)

func TestCPacePrependLenAndLvCat(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"prependEmpty", nil},
		{"prepend1234", []byte("1234")},
		{"prepend127", byteRange(127)},
		{"prepend128", byteRange(128)},
	}
	for _, tc := range cases {
		if got := appendPrependLen(nil, tc.in); !bytes.Equal(got, cpaceVector(t, tc.name)) {
			t.Fatalf("%s: prepend_len = %x", tc.name, got)
		}
		if lebLen(len(tc.in))+len(tc.in) != len(cpaceVector(t, tc.name)) {
			t.Fatalf("%s: lebLen disagrees with prepend_len", tc.name)
		}
	}
	if got := lvCat([]byte("1234"), []byte("5"), nil, []byte("678")); !bytes.Equal(got, cpaceVector(t, "lvCat")) {
		t.Fatalf("lv_cat = %x", got)
	}
	ir1 := append(lvCat([]byte("123"), []byte("PartyA")), lvCat([]byte("234"), []byte("PartyB"))...)
	ir2 := append(lvCat([]byte("3456"), []byte("PartyA")), lvCat([]byte("2345"), []byte("PartyB"))...)
	if !bytes.Equal(ir1, cpaceVector(t, "transcriptIR1")) || !bytes.Equal(ir2, cpaceVector(t, "transcriptIR2")) {
		t.Fatal("transcript_ir layout differs from the draft")
	}
}

func TestCPaceGeneratorVectors(t *testing.T) {
	if !bytes.Equal(cpaceTestCI, mustHex(t, "0b415f696e69746961746f720b425f726573706f6e646572")) {
		t.Fatal("test CI literal is wrong")
	}
	genStr := cpaceGeneratorString(cpaceTestPRS, cpaceTestCI, cpaceTestSID)
	if !bytes.Equal(genStr, cpaceVector(t, "generatorString")) {
		t.Fatalf("generator_string = %x", genStr)
	}
	if digest := sha512.Sum512(genStr); !bytes.Equal(digest[:], cpaceVector(t, "generatorHash")) {
		t.Fatalf("generator hash = %x", digest)
	}
	g, err := cpaceGenerator(cpaceTestPRS, cpaceTestCI, cpaceTestSID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.Bytes(), cpaceVector(t, "generator")) {
		t.Fatalf("generator = %x", g.Bytes())
	}
}

func TestCPaceKeyExchangeVectors(t *testing.T) {
	g, err := cpaceGenerator(cpaceTestPRS, cpaceTestCI, cpaceTestSID)
	if err != nil {
		t.Fatal(err)
	}
	ya, yb := cpaceTestScalar(t, "ya"), cpaceTestScalar(t, "yb")
	Ya, Yb := cpacePublicPoint(ya, g), cpacePublicPoint(yb, g)
	if !bytes.Equal(Ya, cpaceVector(t, "Ya")) || !bytes.Equal(Yb, cpaceVector(t, "Yb")) {
		t.Fatalf("Ya = %x, Yb = %x", Ya, Yb)
	}
	kA, err := cpaceSharedPoint(ya, Yb)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := cpaceSharedPoint(yb, Ya)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kA, cpaceVector(t, "K")) || !bytes.Equal(kB, cpaceVector(t, "K2")) {
		t.Fatalf("K = %x / %x", kA, kB)
	}
	transcript := append(lvCat(Ya, cpaceTestADa), lvCat(Yb, cpaceTestADb)...)
	if !bytes.Equal(transcript, cpaceVector(t, "transcriptIR")) {
		t.Fatalf("transcript_ir = %x", transcript)
	}
	iskInput := append(lvCat([]byte(cpaceDSIISK), cpaceTestSID, kA), transcript...)
	if !bytes.Equal(iskInput, cpaceVector(t, "iskInput")) {
		t.Fatalf("ISK input = %x", iskInput)
	}
	isk := cpaceISK(cpaceTestSID, kA, Ya, cpaceTestADa, Yb, cpaceTestADb)
	if !bytes.Equal(isk[:], cpaceVector(t, "ISK")) {
		t.Fatalf("ISK = %x", isk)
	}
}

func TestCPaceScalarMultVectors(t *testing.T) {
	s := cpaceTestScalar(t, "validS")
	got, err := cpaceSharedPoint(s, cpaceVector(t, "validX"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cpaceVector(t, "validSX")) {
		t.Fatalf("scalar_mult_vfy = %x", got)
	}
	if _, err := cpaceSharedPoint(s, cpaceVector(t, "invalidY1")); err == nil {
		t.Fatal("non-canonical point Y_i1 was accepted")
	}
	if _, err := cpaceSharedPoint(s, cpaceVector(t, "invalidY2")); !errors.Is(err, errCPaceIdentity) {
		t.Fatalf("identity point Y_i2: got %v, want errCPaceIdentity", err)
	}
}

func TestCPaceSampleScalarIsFreshAndNonZero(t *testing.T) {
	a, err := cpaceSampleScalar()
	if err != nil {
		t.Fatal(err)
	}
	b, err := cpaceSampleScalar()
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(ristretto255.NewScalar()) == 1 || a.Equal(b) == 1 {
		t.Fatal("sampled scalars are zero or repeat")
	}
}
