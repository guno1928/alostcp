package core

import "sync"

const (
	defaultFrameCapacity = 64*1024 + 64
	maxPooledFrame       = 1024 * 1024
)

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, defaultFrameCapacity)
		return &b
	},
}

func getFrame(size int) *[]byte {
	frame := framePool.Get().(*[]byte)
	if cap(*frame) < size {
		*frame = make([]byte, size)
	}
	*frame = (*frame)[:size]
	return frame
}

func putFrame(frame *[]byte) {
	if cap(*frame) <= maxPooledFrame {
		framePool.Put(frame)
	}
}
