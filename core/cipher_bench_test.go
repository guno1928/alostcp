package core

var benchSizes = []int{64, 256, 1024, 4096, 16384, 65536}

func sizeName(size int) string {
	switch {
	case size >= 1024:
		return itoa(size/1024) + "KB"
	default:
		return itoa(size) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
