package core

import "sync"

const defaultBufSize = 64 * 1024

var framePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, defaultBufSize+64)
		return &b
	},
}

func getFrame(capacity int) []byte {
	b := *(framePool.Get().(*[]byte))
	if cap(b) < capacity {
		b = make([]byte, capacity)
	} else {
		b = b[:capacity]
	}
	return b
}

func putFrame(b []byte) {
	if cap(b) <= 1024*1024 {
		framePool.Put(&b)
	}
}
