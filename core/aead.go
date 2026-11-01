package core

const (
	tagSize   = 16
	nonceSize = 16
)

type sealer struct {
	engine aegisEngine
	nonce  [nonceSize]byte
}

func (s *sealer) seal(dst, plaintext, ad []byte) {
	s.engine.seal(&s.nonce, dst, plaintext, ad)
	incrementNonce(&s.nonce)
}

func (s *sealer) wipe() {
	s.engine.wipe()
	clear(s.nonce[:])
}

type opener struct {
	engine aegisEngine
	nonce  [nonceSize]byte
}

func (o *opener) open(dst, ciphertext, tag, ad []byte) bool {
	if !o.engine.open(&o.nonce, dst, ciphertext, tag, ad) {
		return false
	}
	incrementNonce(&o.nonce)
	return true
}

func (o *opener) wipe() {
	o.engine.wipe()
	clear(o.nonce[:])
}

func incrementNonce(nonce *[nonceSize]byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
